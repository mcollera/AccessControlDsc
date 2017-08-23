Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'AccessControlResourceHelper\AccessControlResourceHelper.psm1') `
                               -Force

# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
        ErrorPathNotFound = The requested path "{0}" cannot be found.
'@
}


Function Get-TargetResource
{
	[CmdletBinding()]
	[OutputType([Hashtable])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

        [Parameter(Mandatory=$true)]
		[Microsoft.Management.Infrastructure.CimInstance[]]
		$AccessControlList,

		[bool]
		$Force = $false
	)

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"

    if(-not (Test-Path -Path $Path))
    {
        $errorMessage = $LocalizedData.ErrorPathNotFound -f $Path
        throw $errorMessage
    }

    $currentACL = Get-Acl -Path $Path

    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    foreach($Principal in $AccessControlList)
    {
        $CimAccessControlEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

        $PrincipalName = $Principal.Principal
        $ForcePrincipal = $Principal.ForcePrincipal

        $Identity = Resolve-Identity -Identity $PrincipalName
        $currentPrincipalAccess = $currentACL.Access.Where({$_.IdentityReference -eq $Identity.Name})
        foreach($Access in $currentPrincipalAccess)
        {
            $AccessControlType = $Access.AccessControlType.ToString()
            $Rights = $Access.RegistryRights.ToString().Split(',').Trim()
            $Inheritance = (Get-RegistryRuleInheritenceName -InheritanceFlag $Access.InheritanceFlags.value__ -PropagationFlag $Access.PropagationFlags.value__).ToString()

            $CimAccessControlEntries += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlEntry -Property @{
                AccessControlType = $AccessControlType
                Rights = @($Rights)
                Inheritance = $Inheritance
                Ensure = ""
            }
        }

        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlList -Property @{
                        Principal = $PrincipalName
                        ForcePrincipal = $ForcePrincipal
                        AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntries)
                    }
    }

    $ReturnValue = @{
        Force = $Force
        Path = $Path
        AccessControlList = $CimAccessControlList
    }

    return $ReturnValue
}

Function Set-TargetResource
{
	[CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

        [Parameter(Mandatory=$true)]
		[Microsoft.Management.Infrastructure.CimInstance[]]
		$AccessControlList,

		[bool]
		$Force = $false
	)

    if(-not (Test-Path -Path $Path))
    {
        $errorMessage = $LocalizedData.ErrorPathNotFound -f $Path
        throw $errorMessage
    }

    $currentAcl = Get-Acl -Path $Path


    foreach($Principal in $AccessControlList)
    {
        $Results = Get-RegistryResults -Principal $Principal -ACL $currentAcl
        $Expected = $Results.Rules
        $ToBeRemoved = $Results.ToBeRemoved
        $AbsentToBeRemoved = $Results.Absent

        foreach($Rule in $Expected)
        {
            if($Rule.Match -eq $false)
            {
                $currentAcl.AddAccessRule($Rule.Rule)
            }
        }

        $isInherited = $AbsentToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count
        if($isInherited -gt 0)
        {
            $currentAcl.SetAccessRuleProtection($true,$true)
        }
        foreach($Rule in $AbsentToBeRemoved.Rule)
        {
            $currentAcl.RemoveAccessRule($Rule)
        }

        if($Principal.ForcePrincipal)
        {
            $isInherited = $ToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count
            if($isInherited -gt 0)
            {
                $currentAcl.SetAccessRuleProtection($true,$true)
            }
            foreach($Rule in $ToBeRemoved.Rule)
            {
                $currentAcl.RemoveAccessRule($Rule)
            }
        }

        Set-Acl -Path $Path -AclObject $currentAcl

    }
}

Function Test-TargetResource
{
	[CmdletBinding()]
	[OutputType([System.Boolean])]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Path,

        [Parameter(Mandatory=$true)]
		[Microsoft.Management.Infrastructure.CimInstance[]]
		$AccessControlList,

		[bool]
		$Force = $false
	)

    if(-not (Test-Path -Path $Path))
    {
        $errorMessage = $LocalizedData.ErrorPathNotFound -f $Path
        throw $errorMessage
    }

    $currentAcl = Get-Acl -Path $Path


    foreach($Principal in $AccessControlList)
    {
        $Results = Get-RegistryResults -Principal $Principal -ACL $currentAcl
        $Expected = $Results.Rules
        $ToBeRemoved = $Results.ToBeRemoved
        $AbsentToBeRemoved = $Results.Absent

        foreach($Rule in $Expected)
        {
            if($Rule.Match -eq $false)
            {
                return $false
            }
        }

        if($AbsentToBeRemoved.Count)
        {
            return $false
        }

        if($Principal.ForcePrincipal)
        {
            if($ToBeRemoved.Count -gt 0)
            {
                return $false
            }
        }
    }
    return $true
}

Function Get-RegistryResults
{
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]
        $Principal,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.RegistrySecurity]
        $ACL
    )

    $Identity = Resolve-Identity -Identity $Principal.Principal
    $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

    $refrenceObject = @()

    foreach($ace in $Principal.AccessControlEntry)
    {
        $accessMask = 0
        foreach($mask in $ace.Rights)
        {
            $accessMask = $accessMask + ([System.Security.AccessControl.RegistryRights]::Parse([type]::GetType("System.Security.AccessControl.RegistryRights"), $mask)).value__
        }
        $Inheritance = Get-RegistryRuleInheritenceFlags -Inheritance $ace.Inheritance

        $rule = [PSCustomObject]@{
            Rules = [System.Security.AccessControl.RegistryAccessRule]::new($IdentityRef, $accessMask, $Inheritance.InheritanceFlag, $Inheritance.PropagationFlag, $ace.AccessControlType)
            Ensure = $ace.Ensure
        }
        $refrenceObject += $rule
    }

    $actualAce = $ACL.Access.Where({$_.IdentityReference -eq $Identity.Name})

    return Compare-RegistryRules -Expected $refrenceObject -Actual $actualAce
}

Function Compare-RegistryRules
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Expected,

        [Parameter()]
        [System.Security.AccessControl.RegistryAccessRule[]]
        $Actual
    )

    $results = @()
    $ToBeRemoved = @()
    $AbsentToBeRemoved = @()

    $PresentRules = $Expected.Where({$_.Ensure -eq 'Present'}).Rules
    $AbsentRules = $Expected.Where({$_.Ensure -eq 'Absent'}).Rules
    foreach($refrenceObject in $PresentRules)
    {
        $match = $Actual.Where({
            $_.RegistryRights -eq $refrenceObject.RegistryRights -and
            $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
            $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
            $_.AccessControlType -eq $refrenceObject.AccessControlType -and
            $_.IdentityReference -eq $refrenceObject.IdentityReference
        })
        if($match.Count -ge 1)
        {
            $results += [PSCustomObject]@{
                Rule = $refrenceObject
                Match = $true
            }
        }
        else
        {
            $results += [PSCustomObject]@{
                Rule = $refrenceObject
                Match = $false
            }
        }
    }

    foreach($refrenceObject in $Actual)
    {
        $match = $Expected.Rules.Where({
            $_.RegistryRights -eq $refrenceObject.RegistryRights -and
            $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
            $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
            $_.AccessControlType -eq $refrenceObject.AccessControlType -and
            $_.IdentityReference -eq $refrenceObject.IdentityReference
        })
        if($match.Count -eq 0)
        {
            $ToBeRemoved += [PSCustomObject]@{
                Rule = $refrenceObject
            }
        }
    }

    foreach($refrenceObject in $AbsentRules)
    {
        $match = $Actual.Where({
            $_.RegistryRights -eq $refrenceObject.RegistryRights -and
            $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
            $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
            $_.AccessControlType -eq $refrenceObject.AccessControlType -and
            $_.IdentityReference -eq $refrenceObject.IdentityReference
        })
        if($match.Count -gt 0)
        {
            $AbsentToBeRemoved += [PSCustomObject]@{
                Rule = $refrenceObject
            }
        }
    }

    return [PSCustomObject]@{
        Rules = $results
        ToBeRemoved = $ToBeRemoved
        Absent = $AbsentToBeRemoved
    }
}

Function Get-RegistryRuleInheritenceFlags
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$Inheritance
	)

    switch($Inheritance)
    {
        "Key"{
            $InheritanceFlag = "0"
            $PropagationFlag = "0"
            break

        }
        "KeySubkeys"{
            $InheritanceFlag = "1"
            $PropagationFlag = "0"
            break

        }
        "Subkeys"{
            $InheritanceFlag = "1"
            $PropagationFlag = "2"
            break
        }
    }

    return [PSCustomObject]@{
                InheritanceFlag = $InheritanceFlag
                PropagationFlag = $PropagationFlag
            }
}

Function Get-RegistryRuleInheritenceName
{
    [CmdletBinding()]
	param
	(
		[parameter(Mandatory = $true)]
		[System.String]
		$InheritanceFlag,

        [parameter(Mandatory = $true)]
		[System.String]
		$PropagationFlag
	)

    switch("$InheritanceFlag-$PropagationFlag")
    {
        "0-0"{
            return "This Key Only"

        }
        "1-0"{
            return "This Key and Subkeys"

        }
        "1-2"{
            return "Subkeys Only"

        }
    }

    return ""
}