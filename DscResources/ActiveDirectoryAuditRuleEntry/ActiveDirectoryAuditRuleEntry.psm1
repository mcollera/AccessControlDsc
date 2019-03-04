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
        [Parameter(Mandatory=$true)]
        [System.String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    $Path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName

    if(Test-Path -Path $Path)
    {
        $currentACL = Get-Acl -Path $Path -Audit -ErrorAction Stop

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
                $currentPrincipalAccess = $currentACL.Audit.Where({$_.IdentityReference -eq $Identity.Name})

                foreach($Access in $currentPrincipalAccess)
                {
                    $AuditFlags = $Access.AuditFlags.ToString()
                    $ActiveDirectoryRights = $Access.ActiveDirectoryRights.ToString().Split(',').Trim()
                    $InheritanceType = $Access.InheritanceType.ToString()
                    $InheritedObjectType = $Access.InheritedObjectType.ToString()

                    $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName ActiveDirectoryAuditRule -Property @{
                                ActiveDirectoryRights = @($ActiveDirectoryRights)
                                AuditFlags = $AuditFlags
                                InheritanceType = $InheritanceType
                                InheritedObjectType = $InheritedObjectType
                                Ensure = ""
                            }
                }

                $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName ActiveDirectorySystemAccessControlList -Property @{
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
        DistinguishedName = $DistinguishedName
        AccessControlList = $CimAccessControlList
    }

    return $ReturnValue
}

Function Set-TargetResource
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false

    $Path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName

    if (Test-Path -Path $Path)
    {
        $currentAcl = Get-Acl -Path $Path -Audit
        if ($null -ne $currentAcl)
        {
            if ($Force)
            {
                foreach($AccessControlItem in $AccessControlList)
                {
                    $Principal = $AccessControlItem.Principal
                    $Identity = Resolve-Identity -Identity $Principal
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $ACLRules += ConvertTo-ActiveDirectoryAuditRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                }

                $actualAce = $currentAcl.Audit
                $Results = Compare-ActiveDirectoryAuditRule -Expected $ACLRules -Actual $actualAce
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
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $actualAce = $currentAcl.Audit.Where({$_.IdentityReference -eq $Identity.Name})
                    $ACLRules = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                    $Results = Compare-ActiveDirectoryAuditRule -Expected $ACLRules -Actual $actualAce
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
                $currentAcl.SetAuditRuleProtection($true,$true)
                Set-Acl -Path $Path -AclObject $currentAcl
            }

            foreach($Rule in $Expected)
            {
                if($Rule.Match -eq $false)
                {
                    $NonMatch = $Rule.Rule
                    ("Adding audit rule:"),
                    ("> Path                  : '{0}'" -f $Path),
                    ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                    ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                    ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                    ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                    ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType)) |
                    Write-Verbose

                    $currentAcl.AddAuditRule($Rule.Rule)
                }
            }

            foreach($Rule in $AbsentToBeRemoved)
            {
                $NonMatch = $Rule.Rule
                ("Removing audit rule:"),
                ("> Path                  : '{0}'" -f $Path),
                ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType)) |
                Write-Verbose

                $currentAcl.RemoveAuditRule($Rule.Rule)
            }

            foreach($Rule in $ToBeRemoved)
            {
                $NonMatch = $Rule.Rule
                ("Removing audit rule:"),
                ("> Path                  : '{0}'" -f $Path),
                ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType)) |
                Write-Verbose
                $currentAcl.RemoveAuditRule($Rule.Rule)
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
        [Parameter(Mandatory=$true)]
        [System.String]
        $DistinguishedName,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AccessControlList,

        [Parameter()]
        [bool]
        $Force = $false
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false

    $InDesiredState = $True
    $Path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName

    if(Test-Path -Path $Path)
    {
        $currentACL = Get-Acl -Path $Path -Audit

        if ($null -ne $currentACL)
        {
            if ($Force)
            {
                foreach ($AccessControlItem in $AccessControlList)
                {
                    $Principal = $AccessControlItem.Principal
                    $Identity = Resolve-Identity -Identity $Principal
                    $IdentityRef = New-Object System.Security.Principal.NTAccount($Identity.Name)
                    $ACLRules += ConvertTo-ActiveDirectoryAuditRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                }

                $actualAce = $currentAcl.Audit
                $Results = Compare-ActiveDirectoryAuditRule -Expected $ACLRules -Actual $actualAce
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
                    $ACLRules = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $AccessControlItem -IdentityRef $IdentityRef
                    $actualAce = $currentAcl.Audit.Where({$_.IdentityReference -eq $Identity.Name})
                    $Results = Compare-ActiveDirectoryAuditRule -Expected $ACLRules -Actual $actualAce
                    $Expected += $Results.Rules
                    $AbsentToBeRemoved += $Results.Absent

                    if ($AccessControlItem.ForcePrincipal)
                    {
                        $ToBeRemoved += $Results.ToBeRemoved
                    }

                }
            }

            foreach ($Rule in $Expected)
            {
                if ($Rule.Match -eq $false)
                {
                    $NonMatch = $Rule.Rule
                    ("Found missing [present] audit rule:"),
                    ("> Principal             : '{0}'" -f $Principal),
                    ("> Path                  : '{0}'" -f $Path),
                    ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                    ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                    ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                    ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                    ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType)) |
                    Write-Verbose

                    $InDesiredState = $False
                }
            }

            if ($AbsentToBeRemoved.Count -gt 0)
            {
                $NonMatch = $Rule.Rule
                ("Found [absent] audit rule:"),
                ("> Principal             : '{0}'" -f $Principal),
                ("> Path                  : '{0}'" -f $Path),
                ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType))|
                Write-Verbose

                $InDesiredState = $False
            }

            if ($ToBeRemoved.Count -gt 0)
            {
                $NonMatch = $Rule.Rule
                ("Non-matching audit rule found:"),
                ("> Principal             : '{0}'" -f $Principal),
                ("> Path                  : '{0}'" -f $Path),
                ("> IdentityReference     : '{0}'" -f $NonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $NonMatch.ActiveDirectoryRights),
                ("> AuditFlags            : '{0}'" -f $NonMatch.AuditFlags),
                ("> InheritanceType       : '{0}'" -f $NonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $NonMatch.InheritedObjectType)) |
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

Function ConvertTo-ActiveDirectoryAuditRule
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
        # ActiveDirectoryAuditRule overloads require identity, adRights and auditFlags, adding the optional overloads, in order, via if statements
        $auditRuleOverloads = @($IdentityRef, $ace.ActiveDirectoryRights, $ace.AuditFlags)

        if ($null -ne $ace.ObjectType)
        {
            $auditRuleOverloads += $ace.ObjectType
        }

        if ($null -ne $ace.InheritanceType)
        {
            $auditRuleOverloads += $ace.InheritanceType
        }

        if (($null -ne $ace.InheritedObjectType) -and ($null -ne $ace.InheritanceType))
        {
            $auditRuleOverloads += Get-DelegationRightsGuid -ObjectName $ace.InheritedObjectType
        }

        $rule = [PSCustomObject]@{
            Rules  = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAuditRule -ArgumentList $auditRuleOverloads
            Ensure = $ace.Ensure
        }

        $referenceRule += $rule
    }

    return $referenceRule
}

Function Compare-ActiveDirectoryAuditRule
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Expected,

        [Parameter()]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]
        $Actual,

        [Parameter()]
        [bool]
        $Force = $false
    )

    $results = @()
    $ToBeRemoved = @()
    $AbsentToBeRemoved = @()

    $PresentRules = $Expected.Where({$_.Ensure -eq 'Present'}).Rules
    $AbsentRules = $Expected.Where({$_.Ensure -eq 'Absent'}).Rules
    foreach ($referenceRule in $PresentRules)
    {
        $match = Test-ActiveDirectoryAuditRuleMatch -ReferenceRule $referenceRule -DifferenceRule $Actual -Force $Force

        if
        (
            ($match.Count -ge 1) -and
            ($match.ActiveDirectoryRights.value__ -ge $referenceRule.ActiveDirectoryRights.value__)
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
        $match = Test-ActiveDirectoryAuditRuleMatch -ReferenceRule $referenceRule -DifferenceRule $Actual -Force $Force

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
        ToBeRemoved = $ToBeRemoved
        Absent = $AbsentToBeRemoved
    }
}

function Test-ActiveDirectoryAuditRuleMatch
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule[]]
        [AllowEmptyCollection()]
        $DifferenceRule,

        [Parameter(Mandatory = $true)]
        [System.DirectoryServices.ActiveDirectoryAuditRule]
        $ReferenceRule,

        [Parameter(Mandatory = $true)]
        [bool]
        $Force
    )

    if ($Force)
    {
        $DifferenceRule.Where({
            $_.ActiveDirectoryRights -eq $ReferenceRule.ActiveDirectoryRights -and
            $_.AuditFlags -eq $ReferenceRule.AuditFlags -and
            $_.ObjectType -eq $ReferenceRule.ObjectType -and
            $_.InheritanceType -eq $ReferenceRule.InheritanceType -and
            $_.InheritedObjectType -eq $ReferenceRule.InheritedObjectType -and
            $_.IdentityReference -eq $ReferenceRule.IdentityReference
        })
    }
    else
    {
        $DifferenceRule.Where({
            ($_.ActiveDirectoryRights.value__ -band $ReferenceRule.ActiveDirectoryRights.value__) -match
            "$($_.ActiveDirectoryRights.value__)|$($ReferenceRule.ActiveDirectoryRights.value__)" -and
            $_.ObjectType -eq $ReferenceRule.ObjectType -and
            $_.InheritanceType -eq $ReferenceRule.InheritanceType -and
            $_.InheritedObjectType -eq $ReferenceRule.InheritedObjectType -and
            $_.IdentityReference -eq $ReferenceRule.IdentityReference
        })
    }
}
