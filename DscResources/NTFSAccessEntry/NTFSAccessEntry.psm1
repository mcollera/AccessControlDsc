$resourceRoot = Split-Path -Path $PSScriptRoot -Parent
$resourceHelper = Join-Path -Path $resourceRoot -ChildPath 'AccessControlResourceHelper\AccessControlResourceHelper.psm1'
Import-Module -Name $resourceHelper -Force

# Localized messages
data localizedData
{
    # culture = "en-US"
    ConvertFrom-StringData -StringData @'
        ErrorPathNotFound        = The requested path '{0}' cannot be found.
        AclNotFound              = Error obtaining '{0}' ACL.
        AclFound                 = Obtained '{0}' ACL.
        RemoveAccessError        = Unable to remove access for '{0}'.
        InheritanceDetectedForce = Force set to '{0}', Inheritance detected on path '{1}', returning 'false'
        ResetDisableInheritance  = Disabling inheritance and wiping all existing inherited access rules.
        ActionAdd                = Adding access rule:
        ActionRemove             = Removing access rule:
        ActionResetAdd           = Resetting explicit access control list and adding access rule:
        ActionNonMatch           = Non-matching permission entry found:
        ActionMissPresent        = Found missing [Ensure = Present] permission rule:
        ActionAbsent             = Found [Ensure = Absent] permission rule:
        Path                     = > Path              : "{0}"
        IdentityReference        = > IdentityReference : "{0}"
        AccessControlType        = > AccessControlType : "{0}"
        FileSystemRights         = > FileSystemRights  : "{0}"
        InheritanceFlags         = > InheritanceFlags  : "{0}"
        PropagationFlags         = > PropagationFlags  : "{0}"
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

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $nameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $cimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath -ErrorAction Stop
        $currentAcl = $fileSystemItem.GetAccessControl('Access')

        if ($null -ne $currentAcl)
        {
            $message = $localizedData.AclFound -f $inputPath
            Write-Verbose -Message $message

            foreach ($principal in $AccessControlList)
            {
                $cimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

                $principalName = $principal.Principal
                $forcePrincipal = $principal.ForcePrincipal

                $identity = Resolve-Identity -Identity $principalName
                $currentPrincipalAccess = $currentAcl.Access.Where({$_.IdentityReference -eq $identity.Name})

                foreach ($access in $currentPrincipalAccess)
                {
                    $accessControlType = $access.AccessControlType.ToString()
                    $fileSystemRights = $access.FileSystemRights.ToString().Split(',').Trim()
                    $Inheritance = Get-NtfsInheritenceName -InheritanceFlag $access.InheritanceFlags.value__ -PropagationFlag $access.PropagationFlags.value__

                    $cimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName NTFSAccessControlEntry -Property @{
                        AccessControlType = $accessControlType
                        FileSystemRights = @($fileSystemRights)
                        Inheritance = $Inheritance
                        Ensure = ""
                    }
                }

                $cimAccessControlList += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName NTFSAccessControlList -Property @{
                    Principal = $principalName
                    ForcePrincipal = $forcePrincipal
                    AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimAccessControlEntry)
                }
            }

        }
        else
        {
            $message = $localizedData.AclNotFound -f $inputPath
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $localizedData.ErrorPathNotFound -f $inputPath
        Write-Verbose -Message $Message
    }

    $returnValue = @{
        Force = $Force
        Path = $inputPath
        AccessControlList = $cimAccessControlList
    }

    return $returnValue
}

Function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $aclRules = @()

    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath
        $currentAcl = $fileSystemItem.GetAccessControl('Access')

        if ($null -ne $currentAcl)
        {
            if ($Force)
            {
                # If inheritance is set, disable it and clear inherited access rules
                if (-not $currentAcl.AreAccessRulesProtected)
                {
                    Write-Verbose -Message ($localizedData.ResetDisableInheritance)
                    $currentAcl.SetAccessRuleProtection($true, $false)
                }

                # Removing all access rules to ensure a blank list
                if ($null -ne $currentAcl.Access)
                {
                    foreach ($ace in $currentAcl.Access)
                    {
                        $currentAcl.RemoveAccessRuleAll($ace)
                        Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $ace
                    }
                }
            }

            foreach ($accessControlItem in $AccessControlList)
            {
                $principal = $accessControlItem.Principal
                $identity = Resolve-Identity -Identity $principal
                $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)
                $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $identity.Name})
                $aclRules = ConvertTo-FileSystemAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                $results = Compare-NtfsRule -Expected $aclRules -Actual $actualAce -Force $accessControlItem.ForcePrincipal
                $expected += $results.Rules
                $toBeRemoved += $results.Absent

                if ($accessControlItem.ForcePrincipal)
                {
                    $toBeRemoved += $results.ToBeRemoved
                }
            }

            $isInherited = $toBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count

            if ($isInherited -gt 0)
            {
                $currentAcl.SetAccessRuleProtection($true, $true)
                $fileSystemItem.SetAccessControl($currentAcl)
                $currentAcl = $fileSystemItem.GetAccessControl('Access')
            }

            foreach ($rule in $toBeRemoved.Rule)
            {
                try
                {
                    Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $rule
                    $currentAcl.RemoveAccessRuleSpecific($rule)
                }
                catch
                {
                    try
                    {
                        #If failure due to Idenitity translation issue then create the same rule with the identity as a sid to remove account
                        $sid = ConvertTo-SID -IdentityReference $rule.IdentityReference.Value
                        $sidRule = New-Object System.Security.AccessControl.FileSystemRights($sid, $rule.FileSystemRights.value__, $rule.InheritanceFlags.value__, $rule.PropagationFlags.value__, $rule.AccessControlType.value__)
                        Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $sidRule
                        $currentAcl.RemoveAccessRuleSpecific($sidRule)
                    }
                    catch
                    {
                        Write-Verbose -Message ($localizedData.AclNotFound -f $($rule.IdentityReference.Value))
                    }
                }
            }

            foreach ($rule in $expected.Rule)
            {
                Write-CustomVerboseMessage -Action 'ActionAdd' -Path $inputPath -Rule $rule
                $currentAcl.AddAccessRule($rule)
            }

            $fileSystemItem.SetAccessControl($currentAcl)
        }
        else
        {
            Write-Verbose -Message ($localizedData.AclNotFound -f $inputPath)
        }
    }
    else
    {
        Write-Verbose -Message ($localizedData.ErrorPathNotFound -f $inputPath)
    }
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

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $aclRules = @()

    $inDesiredState = $True
    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath
        $currentAcl = $fileSystemItem.GetAccessControl('Access')
        $mappedAcl = Update-FileSystemRightsMapping($currentAcl)

        if ($null -ne $currentAcl)
        {
            if ($Force)
            {
                if ($currentAcl.AreAccessRulesProtected -eq $false)
                {
                    Write-Verbose -Message ($localizedData.InheritanceDetectedForce -f $Force, $inputPath)
                    return $false
                }

                foreach ($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)
                    $aclRules += ConvertTo-FileSystemAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                }

                $actualAce = $mappedAcl.Access
                $results = Compare-NtfsRule -Expected $aclRules -Actual $actualAce -Force $accessControlItem.ForcePrincipal
                $expected = $results.Rules
                $absentToBeRemoved = $results.Absent
                $toBeRemoved = $results.ToBeRemoved
            }
            else
            {
                foreach ($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)
                    $aclRules = ConvertTo-FileSystemAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                    $actualAce = $mappedAcl.Access.Where({$_.IdentityReference -eq $identity.Name})
                    $results = Compare-NtfsRule -Expected $aclRules -Actual $actualAce -Force $accessControlItem.ForcePrincipal
                    $expected += $results.Rules
                    $absentToBeRemoved += $results.Absent

                    if ($accessControlItem.ForcePrincipal)
                    {
                        $toBeRemoved += $results.ToBeRemoved
                    }
                }
            }

            foreach ($rule in $expected)
            {
                if ($rule.Match -eq $false)
                {
                    Write-CustomVerboseMessage -Action 'ActionMissPresent' -Path $inputPath -Rule $rule.rule
                    $inDesiredState = $false
                }
            }

            if ($absentToBeRemoved.Count -gt 0)
            {
                foreach ($rule in $absentToBeRemoved.Rule)
                {
                    Write-CustomVerboseMessage -Action 'ActionAbsent' -Path $inputPath -Rule $rule
                }

                $inDesiredState = $false
            }

            if ($toBeRemoved.Count -gt 0)
            {
                foreach ($rule in $toBeRemoved.Rule)
                {
                    Write-CustomVerboseMessage -Action 'ActionNonMatch' -Path $inputPath -Rule $rule
                }

                $inDesiredState = $false
            }
        }
        else
        {
            Write-Verbose -Message ($localizedData.AclNotFound -f $inputPath)
            $inDesiredState = $false
        }
    }
    else
    {
        Write-Verbose -Message ($localizedData.ErrorPathNotFound -f $inputPath)
        $inDesiredState = $false
    }
    
    return $inDesiredState
}

Function Get-NtfsInheritenceFlag
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
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

    $referenceRule = @()

    foreach ($ace in $AccessControlList.AccessControlEntry)
    {
        $inheritance = Get-NtfsInheritenceFlag -Inheritance $ace.Inheritance
        $rule = [PSCustomObject]@{
            Rules = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $IdentityRef,
                $ace.FileSystemRights,
                $Inheritance.InheritanceFlag,
                $Inheritance.PropagationFlag,
                $ace.AccessControlType
            )
            Ensure = $ace.Ensure
        }

        $referenceRule += $rule
    }

    return $referenceRule
}

Function Compare-NtfsRule
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Expected,

        [Parameter()]
        [System.Security.AccessControl.FileSystemAccessRule[]]
        $Actual,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $results = @()
    $toBeRemoved = @()
    $absentToBeRemoved = @()
    $presentRules = $Expected.Where({$_.Ensure -eq 'Present'}).Rules
    $absentRules = $Expected.Where({$_.Ensure -eq 'Absent'}).Rules

    foreach ($referenceRule in $PresentRules)
    {
        $match = Test-FileSystemAccessRuleMatch -ReferenceRule $referenceRule -DifferenceRule $Actual -Force $Force

        if
        (
            ($match.Count -ge 1) -and
            ($match.FileSystemRights.value__ -ge $referenceRule.FileSystemRights.value__)
        )
        {
            $results += [PSCustomObject]@{
                Rule  = $referenceRule
                Match = $true
            }
        }
        else
        {
            $results += [PSCustomObject]@{
                Rule  = $referenceRule
                Match = $false
            }
        }
    }

    foreach ($referenceRule in $AbsentRules)
    {
        $match = Test-FileSystemAccessRuleMatch -ReferenceRule $referenceRule -DifferenceRule $Actual -Force $Force

        if ($match.Count -gt 0)
        {
            $absentToBeRemoved += [PSCustomObject]@{
                Rule = $match
            }
        }
    }

    foreach ($referenceRule in $Actual)
    {
        $match = Test-FileSystemAccessRuleMatch -ReferenceRule $referenceRule -DifferenceRule $Expected.Rules -Force $Force

        if ($match.Count -eq 0)
        {
            $toBeRemoved += [PSCustomObject]@{
                Rule = $referenceRule
            }
        }
    }

    return [PSCustomObject]@{
        Rules = $results
        ToBeRemoved = $toBeRemoved
        Absent = $absentToBeRemoved
    }
}

Function Update-FileSystemRightsMapping
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $Ace
    )

    foreach ($rule in $Ace.Access)
    {
        $rightsBand = [int]0xf0000000 -band $rule.FileSystemRights.value__
        if (($rightsBand -gt 0) -or ($rightsBand -lt 0))
        {
            $sid = ConvertTo-SID -IdentityReference $rule.IdentityReference
            $mappedRight = Get-MappedGenericRight($rule.FileSystemRights)
            $mappedRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                $sid,
                $mappedRight,
                $rule.InheritanceFlags,
                $rule.PropagationFlags,
                $rule.AccessControlType
            )

            try
            {
                $Ace.RemoveAccessRule($rule)
            }
            catch
            {
                $sidRule = $Ace.AccessRuleFactory(
                    $sid,
                    $rule.FileSystemRights,
                    $rule.IsInherited,
                    $rule.InheritanceFlags,
                    $rule.PropagationFlags,
                    $rule.AccessControlType
                )
                $Ace.RemoveAccessRule($sidRule)
            }
            
            $Ace.AddAccessRule($mappedRule)
        }
    }

    return $Ace
}

Function Get-MappedGenericRight
{
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $Rights
    )

    [int]$genericRead = 0x80000000
    [int]$genericWrite = 0x40000000
    [int]$genericExecute = 0x20000000
    [int]$genericFullControl = 0x10000000
    [int]$fsarGenericRead = (
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::ReadData -bor
        [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    )

    [int]$fsarGenericWrite = (
        [System.Security.AccessControl.FileSystemRights]::AppendData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::WriteData -bor
        [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    )

    [int]$fsarGenericExecute = (
        [System.Security.AccessControl.FileSystemRights]::ExecuteFile -bor
        [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor
        [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor
        [System.Security.AccessControl.FileSystemRights]::Synchronize
    )

    [int]$fsarGenericFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $fsarRights = 0

    if (($Rights -band $genericRead) -eq $genericRead)
    {
        $fsarRights = $fsarRights -bor $fsarGenericRead
    }

    if (($Rights -band $genericWrite) -eq $genericWrite)
    {
        $fsarRights = $fsarRights -bor  $fsarGenericWrite
    }

    if (($Rights -band $genericExecute) -eq $genericExecute)
    {
        $fsarRights = $fsarRights -bor  $fsarGenericExecute
    }

    if (($Rights -band $genericFullControl) -eq $genericFullControl)
    {
        $fsarRights = $fsarRights -bor  $fsarGenericFullControl
    }

    if ($fsarRights -ne 0)
    {
        return $fsarRights
    }

    return $Rights
}

Function Get-InputPath
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $returnPath = $Path

    # If Path has a environment variable, convert it to a locally usable path
    $returnPath = [System.Environment]::ExpandEnvironmentVariables($Path)

    return $returnPath
}

function Write-CustomVerboseMessage
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Action,

        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]
        $Rule
    )

    $properties = @(
        'IdentityReference',
        'AccessControlType',
        'FileSystemRights',
        'InheritanceFlags',
        'PropagationFlags'
    )

    Write-Verbose -Message $localizedData[$Action]
    Write-Verbose -Message ($localizedData.Path -f $Path)

    foreach ($property in $properties)
    {
        $message = $localizedData[$property] -f $Rule.$property
        Write-Verbose -Message $message
    }
}

function Test-FileSystemAccessRuleMatch
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule[]]
        [AllowEmptyCollection()]
        $DifferenceRule,

        [Parameter(Mandatory = $true)]
        [System.Security.AccessControl.FileSystemAccessRule]
        $ReferenceRule,

        [Parameter(Mandatory = $true)]
        [bool]
        $Force
    )

    if ($Force)
    {
        $DifferenceRule.Where({
                $_.FileSystemRights -eq $ReferenceRule.FileSystemRights -and
                $_.InheritanceFlags -eq $ReferenceRule.InheritanceFlags -and
                $_.PropagationFlags -eq $ReferenceRule.PropagationFlags -and
                $_.AccessControlType -eq $ReferenceRule.AccessControlType -and
                $_.IdentityReference -eq $ReferenceRule.IdentityReference
            })
    }
    else
    {
        $DifferenceRule.Where({
                ($_.FileSystemRights.value__ -band $ReferenceRule.FileSystemRights.value__) -match
                "$($_.FileSystemRights.value__)|$($ReferenceRule.FileSystemRights.value__)" -and
                (($_.InheritanceFlags.value__ -eq 3 -and $ReferenceRule.InheritanceFlags.value__ -in 1..3) -or
                ($_.InheritanceFlags.value__ -in 1..3 -and $ReferenceRule.InheritanceFlags.value__ -eq 0) -or
                ($_.InheritanceFlags.value__ -eq $ReferenceRule.InheritanceFlags.value__)) -and
                (($_.PropagationFlags.value__ -eq 3 -and $ReferenceRule.PropagationFlags.value__ -in 1..3) -or
                ($_.PropagationFlags.value__ -in 1..3 -and $ReferenceRule.PropagationFlags.value__ -eq 0) -or
                ($_.PropagationFlags.value__ -eq $ReferenceRule.PropagationFlags.value__)) -and
                $_.AccessControlType -eq $ReferenceRule.AccessControlType -and
                $_.IdentityReference -eq $ReferenceRule.IdentityReference
        })
    }
}
