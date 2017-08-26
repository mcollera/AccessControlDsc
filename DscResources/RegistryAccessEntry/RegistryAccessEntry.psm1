Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
                               -ChildPath 'AccessControlResourceHelper\AccessControlResourceHelper.psm1') `
                               -Force

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

    if(-not (Test-Path -Path $Path))
    {
        Write-host "Throw Error here"
    }

    $Acl = Get-Acl -Path $Path

    $CimAccessControlEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $CimAccessControlLists = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'


    foreach($Principal in $AccessControlList)
    {
        $Identity = Resolve-Identity -Identity $Principal.Principal
        foreach($ACLAccess in $Acl.Access.Where({$_.IdentityReference -eq $Identity.Name}))
        {
            $CimAccessControlEntry = New-CimInstance -ClientOnly `
                    -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                    -ClassName AccessControlEntry `
                    -Property @{
                        AccessControlType = $ACLAccess.AccessControlType.ToString()
                        Rights = $ACLAccess.RegistryRights.ToString()
                        Inheritance = (Get-RegistryRuleInheritenceName -InheritanceFlag $ACLAccess.InheritanceFlags.value__ -PropagationFlag $ACLAccess.PropagationFlags.value__).ToString()
                    }
            $CimAccessControlEntries.Add($CimAccessControlEntry)
        }

        $CimAccessControlList = New-CimInstance -ClientOnly `
                    -Namespace root/Microsoft/Windows/DesiredStateConfiguration `
                    -ClassName AccessControlList `
                    -Property @{
                        Principal = $Principal.Principal.ToString()
                        ForcePrincipal = $Principal.ForcePrincipal
                        AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntries)
                    }
        $CimAccessControlLists.Add($CimAccessControlList)
    }

    $ReturnValue = @{
        Force = $false #ToDo
        Path = $Path
        AccessControlList = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlLists)
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
        Write-host "Throw Error here"
    }

    $Acl = Get-Acl -Path $Path


    foreach($Principal in $AccessControlList)
    {
        $Results = Get-RegistryResults -Principal $Principal -ACl $Acl
        $EnsureResult = $true
        $Expected = $Results[0]
        $ToBeRemoved = $Results[1]

        foreach($Rule in $Expected)
        {
            if($Rule[1] -eq $false)
            {
                $EnsureResult = $false
            }
        }

        if($Principal.ForcePrincipal)
        {
            if($ToBeRemoved.Count -gt 0)
            {
                $EnsureResult = $false
            }
        }
    }


return $EnsureResult
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
        $ACl
    )

    $Identity = Resolve-Identity -Identity $Principal.Principal
    $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)

    [System.Security.AccessControl.RegistryAccessRule[]]$refrenceObject = $null

    foreach($ace in $Principal.AccessControlEntry)
    {
        $accessMask = 0
        foreach($mask in $ace.Rights)
        {
            $accessMask = $accessMask + ([System.Security.AccessControl.RegistryRights]::Parse([type]::GetType("System.Security.AccessControl.RegistryRights"), $mask)).value__
        }
        $Inheritance = Get-RegistryRuleInheritence -Inheritance $ace.Inheritance

        $refrenceObject += [System.Security.AccessControl.RegistryAccessRule]::new($IdentityRef, $mask, $Inheritance.InheritanceFlag, $Inheritance.PropagationFlag, $ace.AccessControlType)

    }

    $actualAce = $Acl.Access.Where({$_.IdentityReference -eq $Identity.Name})

    return Compare-RegistryRules -Expected $refrenceObject -Actual $actualAce
}

Function Compare-RegistryRules
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.RegistryAccessRule[]]
        $Expected,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.RegistryAccessRule[]]
        $Actual
    )

    $results = @()
    $ToBeRemoved = @()

    foreach($refrenceObject in $Expected)
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
            $results += ,@($refrenceObject, $true)
        }
        else
        {
            $results += ,@($refrenceObject, $false)
        }
    }

    foreach($refrenceObject in $Actual)
    {
        $match = $Expected.Where({
            $_.RegistryRights -eq $refrenceObject.RegistryRights -and
            $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
            $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
            $_.AccessControlType -eq $refrenceObject.AccessControlType -and
            $_.IdentityReference -eq $refrenceObject.IdentityReference
        })
        if($match.Count -eq 0)
        {
            $ToBeRemoved += ,@($refrenceObject)
        }
    }

    return @($results, $ToBeRemoved)
}

Function Get-RegistryRuleInheritence
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

        }
        "KeySubkeys"{
            $InheritanceFlag = "1"
            $PropagationFlag = "0"

        }
        "Subkeys"{
            $InheritanceFlag = "1"
            $PropagationFlag = "2"

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
            return "Key"

        }
        "1-0"{
            return "KeySubkeys"

        }
        "1-2"{
            return "Subkeys"

        }
    }

    return ""
}
