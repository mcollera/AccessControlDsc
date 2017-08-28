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

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [bool]
        $Force = $false
    )

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if(Test-Path -Path $Path)
    {
        $currentACL = Get-Acl -Path $Path -ErrorAction Stop

        if($null -ne $currentACL)
        {
            $message = $LocalizedData.AclFound -f $Path
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
            $message = $LocalizedData.AclNotFound -f $Path
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $Path
        Write-Verbose -Message $Message
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
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [bool]
        $Force = $false
    )

    if(Test-Path -Path $Path)
    {
        $currentAcl = Get-Acl -Path $Path
        if($null -ne $currentAcl)
        {
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
                    $NonMatch = $Rule.Rule
                    ("Adding access rule:"),
                    ("> Principal         : '{0}'" -f $Principal),
                    ("> Path              : '{0}'" -f $Path),
                    ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                    Write-Verbose

                    $currentAcl.AddAccessRule($Rule.Rule)
                }
            }

            foreach($Rule in $AbsentToBeRemoved.Rule)
            {
                $NonMatch = $Rule.Rule
                ("Removing access rule:"),
                ("> Principal         : '{0}'" -f $Principal),
                ("> Path              : '{0}'" -f $Path),
                ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                Write-Verbose

                $currentAcl.RemoveAccessRule($Rule)
            }

            foreach($Rule in $ToBeRemoved.Rule)
            {
                try
                {
                    $NonMatch = $Rule.Rule
                    ("Removing access rule:"),
                    ("> Principal         : '{0}'" -f $Principal),
                    ("> Path              : '{0}'" -f $Path),
                    ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                    Write-Verbose
                    $currentAcl.RemoveAccessRule($Rule)
                }
                catch
                {
                    try
                    {
                        #If failure due to Idenitty translation issue then create the same rule with the identity as a sid to remove account
                        $SID = ConvertTo-SID -IdentityReference $Rule.IdentityReference.Value
                        $SIDRule = [System.Security.AccessControl.FileSystemRights]::new($SID, $Rule.FileSystemRights.value__, $Rule.InheritanceFlags.value__, $Rule.PropagationFlags.value__, $Rule.AccessControlType.value__)
                        $currentAcl.RemoveAccessRule($SIDRule)
                    }
                    catch
                    {
                        $message = $LocalizedData.AclNotFound -f $($Rule.IdentityReference.Value)
                        Write-Verbose -Message $message
                    }
                }
            }

            Set-Acl -Path $Path -AclObject $currentAcl
        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $Path
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $Path
        Write-Verbose -Message $Message
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

        [bool]
        $Force = $false
    )

    $InDesiredState = $True
  
    if(Test-Path -Path $Path)
    {
        $currentACL = Get-Acl -Path $Path

        if($null -ne $currentACL)
        {
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
                    $NonMatch = $Rule.Rule
                    ("Found missing [present] permission rule:"),
                    ("> Principal         : '{0}'" -f $Principal),
                    ("> Path              : '{0}'" -f $Path),
                    ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                    ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                    ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                    ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                    ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                    Write-Verbose

                    $InDesiredState = $False
                }
            }

            if($AbsentToBeRemoved.Count -gt 0)
            {
                $NonMatch = $Rule.Rule
                ("Found [absent] permission rule:"),
                ("> Principal         : '{0}'" -f $Principal),
                ("> Path              : '{0}'" -f $Path),
                ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                Write-Verbose

                $InDesiredState = $False
            }

            if($ToBeRemoved.Count -gt 0)
            {
                $NonMatch = $Rule.Rule
                ("Non-matching permission entry found:"),
                ("> Principal         : '{0}'" -f $Principal),
                ("> Path              : '{0}'" -f $Path),
                ("> IdentityReference : '{0}'" -f $NonMatch.IdentityReference),
                ("> AccessControlType : '{0}'" -f $NonMatch.AccessControlType),
                ("> FileSystemRights  : '{0}'" -f $NonMatch.FileSystemRights),
                ("> InheritanceFlags  : '{0}'" -f $NonMatch.InheritanceFlags),
                ("> PropagationFlags  : '{0}'" -f $NonMatch.PropagationFlags) |
                Write-Verbose
                $InDesiredState = $False
            }
        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $Path
            Write-Verbose -Message $message
            $InDesiredState = $False
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $Path
        Write-Verbose -Message $Message
        $InDesiredState = $False
    }
    
    return $InDesiredState
}

Function Get-NtfsInheritenceFlags
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
            $_.FileSystemRights -eq $refrenceObject.FileSystemRights -and
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
            $_.FileSystemRights -eq $refrenceObject.FileSystemRights -and
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
        $match = $Expected.Rules.Where({
            $_.FileSystemRights -eq $refrenceObject.FileSystemRights -and
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
