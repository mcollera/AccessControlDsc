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
        $CimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

        $PrincipalName = $Principal.Principal
        $ForcePrincipal = $Principal.ForcePrincipal

        $Identity = Resolve-Identity -Identity $PrincipalName
        $currentPrincipalAccess = $currentACL.Access.Where({$_.IdentityReference -eq $Identity.Name})

        foreach($Access in $currentPrincipalAccess)
        {
            $AccessControlType = $Access.AccessControlType.ToString()
            $FileSystemRights = $Access.FileSystemRights.ToString().Split(',').Trim()
            $Inheritance = (Get-NtfsInheritenceName -InheritanceFlag $Access.InheritanceFlags.value__ -PropagationFlag $Access.PropagationFlags.value__).ToString()
            
            $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlEntry -Property @{
                        AccessControlType = $AccessControlType
                        FileSystemRights = @($FileSystemRights)
                        Inheritance = $Inheritance
                        Ensure = ""
                    }
        }

        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
                        Principal = $PrincipalName
                        ForcePrincipal = $ForcePrincipal
                        AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntry)
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
    if($null -eq $currentAcl)
    {
        $IsContainer = (Get-Item -Path $Path).PSIsContainer
        If($IsContainer)
        {
            $currentAcl = New-Object -TypeName "System.Security.AccessControl.DirectorySecurity"
        }
        Else
        {
            $currentAcl = New-Object -TypeName "System.Security.AccessControl.FileSecurity"
        }
    }

    if($Force)
    {
        foreach($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

            $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
        }    
        
        $actualAce = $currentAcl.Access

        $Results = Compare-NtfsRules -Expected $ACLRules -Actual $actualAce

        $Expected = $Results.Rules
        $AbsentToBeRemoved = $Results.Absent
        $ToBeRemoved = $Results.ToBeRemoved
    }
    else
    {
        foreach($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

            $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

            $ACLRules = ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
            $Results = Compare-NtfsRules -Expected $ACLRules -Actual $actualAce

            $Expected += $Results.Rules
            $AbsentToBeRemoved += $Results.Absent

            if($AccessControlItem.ForcePrinciPal)
            {
                $ToBeRemoved += $Results.ToBeRemoved
            }
        }
    }

    $isInherited = 0
    $isInherited += $AbsentToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count
    $isInherited += $ToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count

    if($isInherited -gt 0)
    {
        $currentAcl.SetAccessRuleProtection($true,$true)
        Set-Acl -Path $Path -AclObject $currentAcl
    }

    foreach($Rule in $Expected)
    {
        if($Rule.Match -eq $false)
        {
            $currentAcl.AddAccessRule($Rule.Rule)
        }
    }

    foreach($Rule in $AbsentToBeRemoved.Rule)
    {
        $currentAcl.RemoveAccessRule($Rule)
    }

    foreach($Rule in $ToBeRemoved.Rule)
    {
        try
        {
            $currentAcl.RemoveAccessRule($Rule)
        }
        catch
        {
            try
            {
                #If failure due to Idenitty translation issue then create the same rule with the identity as a sid to remove account
                $SID = ConvertTo-SID -IdentityReference $Rule.IdentityReference.Value
                $SIDRule = [System.Security.AccessControl.RegistryAccessRule]::new($SID, $Rule.RegistryRights.value__, $Rule.InheritanceFlags.value__, $Rule.PropagationFlags.value__, $Rule.AccessControlType.value__)
                $currentAcl.RemoveAccessRule($SIDRule)
            }
            catch
            {
                Write-Verbose "Unable to remove Access for $($Rule.IdentityReference.Value)"
            }
        }
    }

    Set-Acl -Path $Path -AclObject $currentAcl
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

    if($Force)
    {
        foreach($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

            $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
        }    
        
        $actualAce = $currentAcl.Access

        $Results = Compare-NtfsRules -Expected $ACLRules -Actual $actualAce

        $Expected = $Results.Rules
        $AbsentToBeRemoved = $Results.Absent
        $ToBeRemoved = $Results.ToBeRemoved
    }
    else
    {
        foreach($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

            $ACLRules = ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef

            $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

            $Results = Compare-NtfsRules -Expected $ACLRules -Actual $actualAce

            $Expected += $Results.Rules
            $AbsentToBeRemoved += $Results.Absent

            if($AccessControlItem.ForcePrinciPal)
            {
                $ToBeRemoved += $Results.ToBeRemoved
            }

        }
    }

    foreach($Rule in $Expected)
    {
        if($Rule.Match -eq $false)
        {
            return $false
        }
    }

    if($AbsentToBeRemoved.Count -gt 0)
    {
        return $false
    }

    if($ToBeRemoved.Count -gt 0)
    {
        return $false
    }

    return $true
}

Function Get-NtfsInheritenceFlags
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
        "This folder only"{
            $InheritanceFlag = "0"
            $PropagationFlag = "0"
            break

        }
        "This folder subfolders and files"{
            $InheritanceFlag = "3"
            $PropagationFlag = "0"
            break

        }
        "This folder and subfolders"{
            $InheritanceFlag = "1"
            $PropagationFlag = "0"
            break
        }
        "This folder and files"{
            $InheritanceFlag = "2"
            $PropagationFlag = "0"
            break

        }
        "Subfolders and files only"{
            $InheritanceFlag = "3"
            $PropagationFlag = "2"
            break

        }
        "Subfolders only"{
            $InheritanceFlag = "1"
            $PropagationFlag = "2"
            break
        }
        "Files only"{
            $InheritanceFlag = "2"
            $PropagationFlag = "2"
            break
        }
    }

    return [PSCustomObject]@{
                InheritanceFlag = $InheritanceFlag
                PropagationFlag = $PropagationFlag
            }
}

Function Get-NtfsInheritenceName
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
            return "This folder only"
        }
        "3-0"{
            return "This folder subfolders and files"
        }
        "1-0"{
            return "This folder and subfolders"
        }
        "2-0"{
            return "This folder and files"
        }
        "3-2"{
            return "Subfolders and files only"
        }
        "1-2"{
            return "Subfolders Only"
        }
        "2-2"{
            return "Files Only"
        }
    }

    return "none"
}

Function ConvertTo-FileSystemAccessRule
{
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance]
        $AccessControlList,

        [Parameter(Mandatory = $true)]
        [System.Security.Principal.NTAccount]
        $IdentityRef
    )

    $refrenceObject = @()

    foreach($ace in $AccessControlList.AccessControlEntry)
    {
        $Inheritance = Get-NtfsInheritenceFlags -Inheritance $ace.Inheritance

        $rule = [PSCustomObject]@{
            Rules = [System.Security.AccessControl.FileSystemAccessRule]::new($IdentityRef, $ace.FileSystemRights, $Inheritance.InheritanceFlag, $Inheritance.PropagationFlag, $ace.AccessControlType)
            Ensure = $ace.Ensure
        }
        $refrenceObject += $rule
    }

    return $refrenceObject
}

Function Compare-NtfsRules
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Expected,

        [Parameter()]
        [System.Security.AccessControl.FileSystemAccessRule[]]
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
