Import-Module -Name (Join-Path -Path (Split-Path $PSScriptRoot -Parent) `
                               -ChildPath 'AccessControlResourceHelper\AccessControlResourceHelper.psm1') `
                               -Force

# Localized messages
data LocalizedData
{
    # culture = "en-US"
    ConvertFrom-StringData -StringData @'
        ErrorPathNotFound       = The requested path '{0}' cannot be found.
        AclNotFound             = Error obtaining '{0}' ACL.
        AclFound                = Obtained '{0}' ACL.
        RemoveAccessError       = Unable to remove access for '{0}'.
        ResetDisableInheritance = Disabling inheritance and wiping all existing access rules.
        ActionAdd               = Adding access rule:
        ActionRemove            = Removing access rule:
        ActionResetAdd          = Resetting access control list and adding access rule:
        ActionNonMatch          = Non-matching permission entry found:
        ActionMissPresent       = Found missing [present] permission rule:
        ActionAbsent            = Found [absent] permission rule:
        Path                    = > Path              : "{0}"
        IdentityReference       = > IdentityReference : "{0}"
        AccessControlType       = > AccessControlType : "{0}"
        FileSystemRights        = > FileSystemRights  : "{0}"
        InheritanceFlags        = > InheritanceFlags  : "{0}"
        PropagationFlags        = > PropagationFlags  : "{0}"
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

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $inputPath = Get-InputPath($Path)

    if(Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath -ErrorAction Stop
        $currentACL = $fileSystemItem.GetAccessControl('Access')

        if($null -ne $currentACL)
        {
            $message = $LocalizedData.AclFound -f $inputPath
            Write-Verbose -Message $message

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
                    $Inheritance = Get-NtfsInheritenceName -InheritanceFlag $Access.InheritanceFlags.value__ -PropagationFlag $Access.PropagationFlags.value__

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

        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $inputPath
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $inputPath
        Write-Verbose -Message $Message
    }

    $ReturnValue = @{
        Force = $Force
        Path = $inputPath
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

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $ACLRules = @()

    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath
        $currentAcl = $fileSystemItem.GetAccessControl('Access')
        if ($null -ne $currentAcl)
        {
            if ($Force)
            {
                if (-not $currentAcl.AreAccessRulesProtected)
                {
                    Write-Verbose -Message ($LocalizedData['ResetDisableInheritance'])
                    $currentAcl.SetAccessRuleProtection($true, $false)
                }

                for ($i = 0; $i -le ($AccessControlList.Count -1); $i++)
                {
                    $Principal = $AccessControlList[$i].Principal
                    $Identity = Resolve-Identity -Identity $Principal
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $aceRule = ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlList[$i] -IdentityRef $IdentityRef
                    if ($i -eq 0)
                    {
                        Write-CustomVerboseMessage -Action 'ActionResetAdd' -Path $inputPath -Rule $aceRule
                        $currentAcl.ResetAccessRule($aceRule)
                    }
                    else
                    {
                        Write-CustomVerboseMessage -Action 'ActionAdd' -Path $inputPath -Rule $aceRule
                        $currentAcl.AddAccessRule($aceRule)
                    }
                }

                $currentAcl.ResetAccessRule($ACLRules)
                $fileSystemItem.SetAccessControl($currentAcl)
            }
            else
            {
                foreach ($AccessControlItem in $AccessControlList)
                {
                    $Principal = $AccessControlItem.Principal
                    $Identity = Resolve-Identity -Identity $Principal
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $actualAce = $currentAcl.Access.Where( {$_.IdentityReference -eq $Identity.Name})
                    $ACLRules = ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                    $Results = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $AccessControlItem.ForcePrincipal
                    $Expected += $Results.Rules
                    $AbsentToBeRemoved += $Results.Absent

                    if ($AccessControlItem.ForcePrincipal)
                    {
                        $ToBeRemoved += $Results.ToBeRemoved
                    }
                }

                $isInherited = 0
                $isInherited += $AbsentToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count
                $isInherited += $ToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count

                if($isInherited -gt 0)
                {
                    $currentAcl.SetAccessRuleProtection($true, $true)
                    $fileSystemItem.SetAccessControl($currentAcl)
                    $currentAcl = $fileSystemItem.GetAccessControl('Access')
                }

                foreach($Rule in $ToBeRemoved.Rule)
                {
                    try
                    {
                        Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $rule
                        $currentAcl.RemoveAccessRuleSpecific($Rule)
                    }
                    catch
                    {
                        try
                        {
                            #If failure due to Idenitity translation issue then create the same rule with the identity as a sid to remove account
                            $SID = ConvertTo-SID -IdentityReference $Rule.IdentityReference.Value
                            $SIDRule = New-Object System.Security.AccessControl.FileSystemRights($SID, $Rule.FileSystemRights.value__, $Rule.InheritanceFlags.value__, $Rule.PropagationFlags.value__, $Rule.AccessControlType.value__)
                            Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $SIDRule
                            $currentAcl.RemoveAccessRuleSpecific($SIDRule)
                        }
                        catch
                        {
                            Write-Verbose -Message ($LocalizedData.AclNotFound -f $($Rule.IdentityReference.Value))
                        }
                    }
                }

                foreach($rule in $AbsentToBeRemoved.Rule)
                {
                    Write-CustomVerboseMessage -Action 'ActionRemove' -Path $inputPath -Rule $rule
                    $currentAcl.RemoveAccessRuleSpecific($rule)
                }

                foreach ($rule in $Expected.Rule)
                {
                    Write-CustomVerboseMessage -Action 'ActionAdd' -Path $inputPath -Rule $rule
                    $currentAcl.AddAccessRule($rule)
                }

                $fileSystemItem.SetAccessControl($currentAcl)
            }
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.AclNotFound -f $inputPath)
        }
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.ErrorPathNotFound -f $inputPath)
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

    $ACLRules = @()

    $InDesiredState = $True
    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        $fileSystemItem = Get-Item -Path $inputPath
        $currentACL = $fileSystemItem.GetAccessControl('Access')
        $mappedACL = Update-FileSystemRightsMapping($currentAcl)

        if ($null -ne $currentACL)
        {
            if ($Force)
            {
                if ($acl.AreAccessRulesProtected -eq $false)
                {
                    return $false
                }

                foreach ($AccessControlItem in $AccessControlList)
                {
                    $Principal = $AccessControlItem.Principal
                    $Identity = Resolve-Identity -Identity $Principal
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                }

                $actualAce = $mappedACL.Access
                $Results = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $AccessControlItem.ForcePrincipal
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
                    $ACLRules = ConvertTo-FileSystemAccessRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                    $actualAce = $mappedACL.Access.Where( {$_.IdentityReference -eq $Identity.Name})
                    $Results = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $AccessControlItem.ForcePrincipal
                    $Expected += $Results.Rules
                    $AbsentToBeRemoved += $Results.Absent

                    if ($AccessControlItem.ForcePrincipal)
                    {
                        $ToBeRemoved += $Results.ToBeRemoved
                    }
                }
            }

            foreach ($rule in $Expected)
            {
                if ($rule.Match -eq $false)
                {
                    Write-CustomVerboseMessage -Action 'ActionMissPresent' -Path $inputPath -Rule $rule.rule
                    $InDesiredState = $False
                }
            }

            if ($AbsentToBeRemoved.Count -gt 0)
            {
                foreach ($rule in $AbsentToBeRemoved)
                {
                    Write-CustomVerboseMessage -Action 'ActionAbsent' -Path $inputPath -Rule $rule
                }

                $InDesiredState = $False
            }

            if ($ToBeRemoved.Count -gt 0)
            {
                foreach ($rule in $ToBeRemoved)
                {
                    Write-CustomVerboseMessage -Action 'ActionNonMatch' -Path $inputPath -Rule $rule
                }

                $InDesiredState = $False
            }
        }
        else
        {
            Write-Verbose -Message ($LocalizedData.AclNotFound -f $inputPath)
            $InDesiredState = $False
        }
    }
    else
    {
        Write-Verbose -Message ($LocalizedData.ErrorPathNotFound -f $inputPath)
        $InDesiredState = $False
    }

    return $InDesiredState
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

    $refrenceObject = @()

    foreach($ace in $AccessControlList.AccessControlEntry)
    {
        $Inheritance = Get-NtfsInheritenceFlag -Inheritance $ace.Inheritance
        $rule = [PSCustomObject]@{
            Rules  = New-Object System.Security.AccessControl.FileSystemAccessRule($IdentityRef, $ace.FileSystemRights, $Inheritance.InheritanceFlag, $Inheritance.PropagationFlag, $ace.AccessControlType)
            Ensure = $ace.Ensure
        }

        $refrenceObject += $rule
    }

    return $refrenceObject
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
    $ToBeRemoved = @()
    $AbsentToBeRemoved = @()
    $PresentRules = $Expected.Where({$_.Ensure -eq 'Present'}).Rules
    $AbsentRules = $Expected.Where( {$_.Ensure -eq 'Absent'}).Rules

    foreach($refrenceObject in $PresentRules)
    {
        $match = $Actual.Where({
            (((($_.FileSystemRights.value__ -band $refrenceObject.FileSystemRights.value__) -match "$($_.FileSystemRights.value__)|$($refrenceObject.FileSystemRights.value__)") -and !$Force) -or ($_.FileSystemRights -eq $refrenceObject.FileSystemRights -and $Force)) -and
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

    foreach($refrenceObject in $AbsentRules)
    {
        $match = $Actual.Where({
            (((($_.FileSystemRights.value__ -band $refrenceObject.FileSystemRights.value__) -match "$($_.FileSystemRights.value__)|$($refrenceObject.FileSystemRights.value__)") -and !$Force) -or ($_.FileSystemRights -eq $refrenceObject.FileSystemRights -and $Force)) -and
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

    foreach($refrenceObject in $Actual)
    {
        $match = @($Expected.Rules).Where({
            (((($_.FileSystemRights.value__ -band $refrenceObject.FileSystemRights.value__) -match "$($_.FileSystemRights.value__)|$($refrenceObject.FileSystemRights.value__)") -and !$Force) -or ($_.FileSystemRights -eq $refrenceObject.FileSystemRights -and $Force)) -and
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

    return [PSCustomObject]@{
        Rules = $results
        ToBeRemoved = $ToBeRemoved
        Absent = $AbsentToBeRemoved
    }
}

Function Update-FileSystemRightsMapping
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Object]
        $ACE
    )

    foreach($Rule in $ACE.Access)
    {
        $rightsBand = [int]0xf0000000 -band $Rule.FileSystemRights.value__
        if( ($rightsBand -gt 0) -or ($rightsBand -lt 0) )
        {
            $SID = ConvertTo-SID -IdentityReference $Rule.IdentityReference
            $mappedRight = Get-MappedGenericRight($Rule.FileSystemRights)
            $mappedRule = New-Object System.Security.AccessControl.FileSystemAccessRule($SID, $mappedRight, $Rule.InheritanceFlags, $Rule.PropagationFlags, $Rule.AccessControlType)

            try
            {
                $ACE.RemoveAccessRule($Rule)
            }
            catch
            {
                $sidRule = $ACE.AccessRuleFactory($SID, $Rule.FileSystemRights, $Rule.IsInherited , $Rule.InheritanceFlags, $Rule.PropagationFlags, $Rule.AccessControlType)
                $ACE.RemoveAccessRule($sidRule)
            }

            $ACE.AddAccessRule($mappedRule)
        }
    }

    return $ACE
}

Function Get-MappedGenericRight
{
    param
    (
        [Parameter(Mandatory = $true)]
        [int]
        $Rights
    )

    [int]$GenericRead = 0x80000000
    [int]$GenericWrite = 0x40000000
    [int]$GenericExecute = 0x20000000
    [int]$GenericFullControl = 0x10000000
    [int]$FsarGenericRead = ([System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor [System.Security.AccessControl.FileSystemRights]::ReadData -bor [System.Security.AccessControl.FileSystemRights]::ReadExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
    [int]$FsarGenericWrite = ([System.Security.AccessControl.FileSystemRights]::AppendData -bor [System.Security.AccessControl.FileSystemRights]::WriteAttributes -bor [System.Security.AccessControl.FileSystemRights]::WriteData -bor [System.Security.AccessControl.FileSystemRights]::WriteExtendedAttributes -bor [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
    [int]$FsarGenericExecute = ([System.Security.AccessControl.FileSystemRights]::ExecuteFile -bor [System.Security.AccessControl.FileSystemRights]::ReadPermissions -bor [System.Security.AccessControl.FileSystemRights]::ReadAttributes -bor [System.Security.AccessControl.FileSystemRights]::Synchronize)
    [int]$FsarGenericFullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    $FsarRights = 0

    if (($Rights -band $GenericRead) -eq $GenericRead)
    {
        $FsarRights = $FsarRights -bor $FsarGenericRead
    }

    if (($Rights -band $GenericWrite) -eq $GenericWrite)
    {
        $FsarRights = $FsarRights -bor  $FsarGenericWrite
    }

    if (($Rights -band $GenericExecute) -eq $GenericExecute)
    {
        $FsarRights = $FsarRights -bor  $FsarGenericExecute
    }

    if (($Rights -band $GenericFullControl) -eq $GenericFullControl)
    {
        $FsarRights = $FsarRights -bor  $FsarGenericFullControl
    }

    if ($FsarRights -ne 0)
    {
        return $FsarRights
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

    Write-Verbose -Message $LocalizedData[$Action]
    Write-Verbose -Message ($LocalizedData[$Path] -f $Path)

    foreach ($property in $properties)
    {
        $message = $LocalizedData[$property] -f $Rule.$property
        Write-Verbose -Message $message
    }
}
