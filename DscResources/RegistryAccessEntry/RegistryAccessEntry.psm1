Import-Module -Name (Join-Path -Path ( Split-Path $PSScriptRoot -Parent ) `
        -ChildPath 'AccessControlResourceHelper\AccessControlResourceHelper.psm1') `
    -Force

# Localized messages
data LocalizedData
{
    # culture="en-US"
    ConvertFrom-StringData -StringData @'
        ErrorPathNotFound = The requested path "{0}" cannot be found.
        AclNotFound = Error obtaining "{0}" ACL
        AclFound = Obtained "{0}" ACL
        RemoveAccessError = "Unable to remove Access for "{0}"
'@
}

Function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"

    if (-not (Test-Path -Path $Path))
    {
        $message = $LocalizedData.ErrorPathNotFound -f $Path
        Write-Verbose -Message $message
    }

    $currentACL = Get-Acl -Path $Path

    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($null -ne $currentACL)
    {
        $message = $LocalizedData.AclFound -f $Path
        Write-Verbose -Message $message

        foreach ($Principal in $AccessControlList)
        {
            $CimAccessControlEntries = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

            $PrincipalName = $Principal.Principal
            $ForcePrincipal = $Principal.ForcePrincipal

            $Identity = Resolve-Identity -Identity $PrincipalName
            $currentPrincipalAccess = $currentACL.Access.Where( {$_.IdentityReference -eq $Identity.Name})
            foreach ($Access in $currentPrincipalAccess)
            {
                $AccessControlType = $Access.AccessControlType.ToString()
                $Rights = $Access.RegistryRights.ToString().Split(',').Trim()
                $Inheritance = (Get-RegistryRuleInheritenceName -InheritanceFlag $Access.InheritanceFlags.value__ -PropagationFlag $Access.PropagationFlags.value__).ToString()

                $CimAccessControlEntries += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlEntry -Property @{
                    AccessControlType = $AccessControlType
                    Rights            = @($Rights)
                    Inheritance       = $Inheritance
                    Ensure            = ""
                }
            }

            $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlList -Property @{
                Principal          = $PrincipalName
                ForcePrincipal     = $ForcePrincipal
                AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntries)
            }
        }
    }
    else
    {
        $message = $LocalizedData.AclNotFound -f $Path
        Write-Verbose -Message $message
    }

    $ReturnValue = @{
        Force             = $Force
        Path              = $Path
        AccessControlList = $CimAccessControlList
    }

    return $ReturnValue
}

Function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $ACLRules = @()

    if (-not (Test-Path -Path $Path))
    {
        $errorMessage = $LocalizedData.ErrorPathNotFound -f $Path
        throw $errorMessage
    }

    $currentAcl = Get-Acl -Path $Path
    if ($null -eq $currentAcl)
    {
        $currentAcl = New-Object -TypeName "System.Security.AccessControl.RegistrySecurity"
    }

    if ($Force)
    {
        foreach ($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)

            $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
        }

        $actualAce = $currentAcl.Access

        $Results = Compare-RegistryRule -Expected $ACLRules -Actual $actualAce

        $Expected = $Results.Rules
        $AbsentToBeRemoved = $Results.Absent
        $ToBeRemoved = $Results.ToBeRemoved
    }
    else
    {
        foreach ($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)

            $actualAce = $currentAcl.Access.Where( {$_.IdentityReference -eq $Identity.Name})

            $ACLRules = ConvertTo-RegistryAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
            $Results = Compare-RegistryRule -Expected $ACLRules -Actual $actualAce

            $Expected += $Results.Rules
            $AbsentToBeRemoved += $Results.Absent

            if ($AccessControlItem.ForcePrinciPal)
            {
                $ToBeRemoved += $Results.ToBeRemoved
            }
        }
    }
    $isInherited = 0
    $isInherited += $AbsentToBeRemoved.Rule.Where( {$_.IsInherited -eq $true}).Count
    $isInherited += $ToBeRemoved.Rule.Where( {$_.IsInherited -eq $true}).Count

    if ($isInherited -gt 0)
    {
        $currentAcl.SetAccessRuleProtection($true, $true)
        Set-Acl -Path $Path -AclObject $currentAcl
    }

    foreach ($Rule in $AbsentToBeRemoved.Rule)
    {
        $currentAcl.RemoveAccessRule($Rule)
    }

    foreach ($Rule in $ToBeRemoved.Rule)
    {
        try
        {
            $currentAcl.RemoveAccessRule($Rule)
        }
        catch
        {
            try
            {
                #If failure due to Identity translation issue then create the same rule with the identity as a sid to remove account
                $SIDRule = ConvertTo-SidIdentityRegistryAccessRule -Rule $Rule
                $currentAcl.RemoveAccessRule($SIDRule)
            }
            catch
            {
                $message = $LocalizedData.AclNotFound -f $($Rule.IdentityReference.Value)
                Write-Verbose -Message $message
            }
        }
    }

    foreach ($Rule in $Expected)
    {
        if ($Rule.Match -eq $false)
        {
            try
            {
                $currentAcl.AddAccessRule($Rule.Rule)
            }
            catch
            {
                try
                {
                    #If failure due to Identity translation issue then create the same rule with the identity as a sid to remove account
                    $SIDRule = ConvertTo-SidIdentityRegistryAccessRule -Rule $Rule
                    $currentAcl.AddAccessRule($Rule.Rule)
                }
                catch
                {
                    $message = $LocalizedData.AclNotFound -f $($Rule.IdentityReference.Value)
                    Write-Verbose -Message $message
                }
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
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $ACLRules = @()

    if (-not (Test-Path -Path $Path))
    {
        $LocalizedData.ErrorPathNotFound -f $Path | Write-Verbose
        return $true
    }

    $currentAcl = Get-Acl -Path $Path

    if ($Force)
    {
        foreach ($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)

            $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
        }

        $actualAce = $currentAcl.Access

        $Results = Compare-RegistryRule -Expected $ACLRules -Actual $actualAce

        $Expected = $Results.Rules
        $AbsentToBeRemoved = $Results.Absent
        $ToBeRemoved = $Results.ToBeRemoved
    }
    else
    {
        foreach ($AccessControlItem in $AccessControlList)
        {
            $Principal = $AccessControlItem.Principal
            $Identity = Resolve-Identity -Identity $Principal
            $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)

            $ACLRules = ConvertTo-RegistryAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef

            $actualAce = $currentAcl.Access.Where( {$_.IdentityReference -eq $Identity.Name})

            $Results = Compare-RegistryRule -Expected $ACLRules -Actual $actualAce

            $Expected += $Results.Rules
            $AbsentToBeRemoved += $Results.Absent

            if ($AccessControlItem.ForcePrinciPal)
            {
                $ToBeRemoved += $Results.ToBeRemoved
            }

        }
    }

    foreach ($Rule in $Expected)
    {
        if ($Rule.Match -eq $false)
        {
            return $false
        }
    }

    if ($AbsentToBeRemoved.Count -gt 0)
    {
        return $false
    }

    if ($ToBeRemoved.Count -gt 0)
    {
        return $false
    }

    return $true
}

Function ConvertTo-RegistryAccessRule
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

    foreach ($ace in $AccessControlList.AccessControlEntry)
    {
        $Inheritance = Get-RegistryRuleInheritenceFlag -Inheritance $ace.Inheritance

        $rule = [PSCustomObject]@{
            Rules  = New-Object System.Security.AccessControl.RegistryAccessRule($IdentityRef, $ace.Rights, $Inheritance.InheritanceFlag, $Inheritance.PropagationFlag, $ace.AccessControlType)
            Ensure = $ace.Ensure
        }
        $refrenceObject += $rule
    }

    return $refrenceObject
}

Function Compare-RegistryRule
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

    $PresentRules = $Expected.Where( {$_.Ensure -eq 'Present'}).Rules
    $AbsentRules = $Expected.Where( {$_.Ensure -eq 'Absent'}).Rules
    foreach ($refrenceObject in $PresentRules)
    {
        $match = $Actual.Where( {
                $_.RegistryRights -eq $refrenceObject.RegistryRights -and
                $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
                $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
                $_.AccessControlType -eq $refrenceObject.AccessControlType -and
                $_.IdentityReference -eq $refrenceObject.IdentityReference
            })
        if ($match.Count -ge 1)
        {
            $results += [PSCustomObject]@{
                Rule  = $refrenceObject
                Match = $true
            }
        }
        else
        {
            $results += [PSCustomObject]@{
                Rule  = $refrenceObject
                Match = $false
            }
        }
    }

    foreach ($refrenceObject in $Actual)
    {
        $match = @($Expected.Rules).Where( {
                $_.RegistryRights -eq $refrenceObject.RegistryRights -and
                $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
                $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
                $_.AccessControlType -eq $refrenceObject.AccessControlType -and
                $_.IdentityReference -eq $refrenceObject.IdentityReference
            })
        if ($match.Count -eq 0)
        {
            $ToBeRemoved += [PSCustomObject]@{
                Rule = $refrenceObject
            }
        }
    }

    foreach ($refrenceObject in $AbsentRules)
    {
        $match = $Actual.Where( {
                $_.RegistryRights -eq $refrenceObject.RegistryRights -and
                $_.InheritanceFlags -eq $refrenceObject.InheritanceFlags -and
                $_.PropagationFlags -eq $refrenceObject.PropagationFlags -and
                $_.AccessControlType -eq $refrenceObject.AccessControlType -and
                $_.IdentityReference -eq $refrenceObject.IdentityReference
            })
        if ($match.Count -gt 0)
        {
            $AbsentToBeRemoved += [PSCustomObject]@{
                Rule = $refrenceObject
            }
        }
    }

    return [PSCustomObject]@{
        Rules       = $results
        ToBeRemoved = $ToBeRemoved
        Absent      = $AbsentToBeRemoved
    }
}

Function Get-RegistryRuleInheritenceFlag
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Inheritance
    )

    switch ($Inheritance)
    {
        "Key"
        {
            $InheritanceFlag = "0"
            $PropagationFlag = "0"
            break

        }
        "KeySubkeys"
        {
            $InheritanceFlag = "1"
            $PropagationFlag = "0"
            break

        }
        "Subkeys"
        {
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
    [OutputType([System.String])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $InheritanceFlag,

        [Parameter(Mandatory = $true)]
        [System.String]
        $PropagationFlag
    )

    switch ("$InheritanceFlag-$PropagationFlag")
    {
        "0-0"
        {
            return "This Key Only"

        }
        "1-0"
        {
            return "This Key and Subkeys"

        }
        "1-2"
        {
            return "Subkeys Only"

        }
    }

    return "none"
}

<#
    .SYNOPSIS
    Takes a Rule object and converts the Principle Name to a SID

    .PARAMETER Rule
    A single Registry Access Rule to be converted

    .EXAMPLE
    $sidRule = ConvertTo-SidIdentityRegistryAccessRule -Rule $Rule

    .NOTES
    This function was created to address translation issues with accounts such as
    'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES'.
#>

function ConvertTo-SidIdentityRegistryAccessRule
{
    [CmdletBinding()]
    [OutputType([System.Security.AccessControl.RegistryAccessRule])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.RegistryAccessRule]
        $Rule
    )

    if ($Rule.IdentityReference.Value.Contains('\'))
    {
        [System.Security.Principal.NTAccount]$PrinicipalName = $Rule.IdentityReference.Value.split('\')[1]
    }
    else
    {
        [System.Security.Principal.NTAccount]$PrinicipalName = $Rule.IdentityReference.Value
    }

    $SID = $PrinicipalName.Translate([System.Security.Principal.SecurityIdentifier])
    $SIDRule = New-Object System.Security.AccessControl.RegistryAccessRule($SID, $Rule.RegistryRights.value__, $Rule.InheritanceFlags.value__, $Rule.PropagationFlags.value__, $Rule.AccessControlType.value__)

    return $SIDRule
}
