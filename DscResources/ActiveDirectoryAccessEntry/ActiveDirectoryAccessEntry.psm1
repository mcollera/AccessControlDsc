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
        $AccessControlList
    )
    
    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false
    
    $namespace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $cimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    $path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName

    if(Test-Path -Path $path)
    {
        $currentAcl = Get-Acl -Path $path -ErrorAction Stop

        if($null -ne $currentAcl)
        {
            $message = $LocalizedData.AclFound -f $path
            Write-Verbose -Message $message
            
            foreach($principal in $AccessControlList)
            {
                $cimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

                $principalName = $principal.Principal
                $ForcePrincipal = $principal.ForcePrincipal

                $identity = Resolve-Identity -Identity $principalName
                $currentPrincipalAccess = $currentAcl.Access.Where({$_.IdentityReference -eq $identity.Name})

                foreach($Access in $currentPrincipalAccess)
                {
                    $ActiveDirectoryRights = $Access.ActiveDirectoryRights.ToString().Split(',').Trim()
                    $InheritanceType = $Access.InheritanceType.ToString()
                    $inheritedObjectType = $Access.InheritedObjectType.ToString()

                    $cimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $namespace -ClassName ActiveDirectoryAccessRule -Property @{
                                ActiveDirectoryRights = @($ActiveDirectoryRights)
                                InheritanceType = $InheritanceType
                                InheritedObjectType = $inheritedObjectType
                                Ensure = ""
                            }
                }

                $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $namespace -ClassName ActiveDirectorySystemAccessControlList -Property @{
                                Principal = $principalName
                                ForcePrincipal = $ForcePrincipal
                                AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimAccessControlEntry)
                            }
            }
        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $path
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $path
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
        $AccessControlList
    )
 
    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false
 
    $path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName
    
    if(Test-Path -Path $path)
    {
        $currentAcl = Get-Acl -Path $path
        if($null -ne $currentAcl)
        {
            if($Force)
            {
                foreach($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)

                    $aclRules += ConvertTo-ActiveDirectoryAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                }    
        
                $actualAce = $currentAcl.Access

                $results = Compare-ActiveDirectoryAccessRule -Expected $aclRules -Actual $actualAce

                $expected = $results.Rules
                $absentToBeRemoved = $results.Absent
                $toBeRemoved = $results.ToBeRemoved
            }
            else
            {
                foreach($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)

                    $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $identity.Name})

                    $aclRules = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                    $results = Compare-ActiveDirectoryAccessRule -Expected $aclRules -Actual $actualAce

                    $expected += $results.Rules
                    $absentToBeRemoved += $results.Absent

                    if($accessControlItem.ForcePrinciPal)
                    {
                        $toBeRemoved += $results.ToBeRemoved
                    }
                }
            }

            $isInherited = 0
            $isInherited += $absentToBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count
            $isInherited += $toBeRemoved.Rule.Where({$_.IsInherited -eq $true}).Count

            if($isInherited -gt 0)
            {
                $currentAcl.SetAccessRuleProtection($true,$true)
                Set-Acl -Path $path -AclObject $currentAcl
            }

            foreach($rule in $expected)
            {
                if($rule.Match -eq $false)
                {
                    $nonMatch = $rule.Rule
                    ("Adding Access rule:"),
                    ("> Path                  : '{0}'" -f $path),
                    ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                    ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                    ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                    ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                    ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType)) |
                    Write-Verbose

                    $currentAcl.AddAccessRule($rule.Rule)
                }
            }

            foreach($rule in $absentToBeRemoved.Rule)
            {
                $nonMatch = $rule.Rule
                ("Removing Access rule:"),
                ("> Path                  : '{0}'" -f $path),
                ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType)) |
                Write-Verbose

                $currentAcl.RemoveAccessRule($rule)
            }

            foreach($rule in $toBeRemoved.Rule)
            {
                $nonMatch = $rule.Rule
                ("Removing Access rule:"),
                ("> Path                  : '{0}'" -f $path),
                ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType)) |
                Write-Verbose
                $currentAcl.RemoveAccessRule($rule)
            }

            Set-Acl -Path $path -AclObject $currentAcl
        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $path
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $LocalizedData.ErrorPathNotFound -f $path
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
        $AccessControlList
    )

    Assert-Module -ModuleName 'ActiveDirectory'
    Import-Module -Name 'ActiveDirectory' -Verbose:$false

    $inDesiredState = $True
    $path = Join-Path -Path "ad:\" -ChildPath $DistinguishedName
    
    if(Test-Path -Path $path)
    {
        $currentAcl = Get-Acl -Path $path

        if($null -ne $currentAcl)
        {
            if($Force)
            {
                foreach($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)

                    $aclRules += ConvertTo-ActiveDirectoryAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef
                }    
        
                $actualAce = $currentAcl.Access

                $results = Compare-ActiveDirectoryAccessRule -Expected $aclRules -Actual $actualAce

                $expected = $results.Rules
                $absentToBeRemoved = $results.Absent
                $toBeRemoved = $results.ToBeRemoved
            }
            else
            {
                foreach($accessControlItem in $AccessControlList)
                {
                    $principal = $accessControlItem.Principal
                    $identity = Resolve-Identity -Identity $principal
                    $identityRef = New-Object System.Security.Principal.NTAccount($identity.Name)

                    $aclRules = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $accessControlItem -IdentityRef $identityRef

                    $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $identity.Name})

                    $results = Compare-ActiveDirectoryAccessRule -Expected $aclRules -Actual $actualAce

                    $expected += $results.Rules
                    $absentToBeRemoved += $results.Absent

                    if($accessControlItem.ForcePrincipal)
                    {
                        $toBeRemoved += $results.ToBeRemoved
                    }

                }
            }

            foreach($rule in $expected)
            {
                if($rule.Match -eq $false)
                {
                    $nonMatch = $rule.Rule
                    ("Found missing [present] Access rule:"),
                    ("> Principal             : '{0}'" -f $principal),
                    ("> Path                  : '{0}'" -f $path),
                    ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                    ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                    ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                    ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                    ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType)) |
                    Write-Verbose

                    $inDesiredState = $False
                }
            }

            if($absentToBeRemoved.Count -gt 0)
            {
                $nonMatch = $rule.Rule
                ("Found [absent] Access rule:"),
                ("> Principal             : '{0}'" -f $principal),
                ("> Path                  : '{0}'" -f $path),
                ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType))|
                Write-Verbose

                $inDesiredState = $False
            }

            if($toBeRemoved.Count -gt 0)
            {
                $nonMatch = $rule.Rule
                ("Non-matching Access rule found:"),
                ("> Principal             : '{0}'" -f $principal),
                ("> Path                  : '{0}'" -f $path),
                ("> IdentityReference     : '{0}'" -f $nonMatch.IdentityReference),
                ("> ActiveDirectoryRights : '{0}'" -f $nonMatch.ActiveDirectoryRights),
                ("> AccessControlType     : '{0}'" -f $nonMatch.AccessControlType),
                ("> InheritanceType       : '{0}'" -f $nonMatch.InheritanceType),
                ("> InheritedObjectType   : '{0}'" -f $(Get-SchemaObjectName -SchemaIdGuid $nonMatch.InheritedObjectType)) |
                Write-Verbose
                $inDesiredState = $False
            }
        }
        else
        {
            $message = $LocalizedData.AclNotFound -f $path
            Write-Verbose -Message $message
            $inDesiredState = $False
        }
    }
    else
    {
        $message = $LocalizedData.ErrorPathNotFound -f $path
        Write-Verbose -Message $Message
        $inDesiredState = $False
    }
    
    return $inDesiredState
}

Function ConvertTo-ActiveDirectoryAccessRule
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

    $referenceObject = @()

    foreach($ace in $AccessControlList.AccessControlEntry)
    {
        $inheritedObjectType = Get-SchemaIdGuid -ObjectName $ace.InheritedObjectType
        $rule = [PSCustomObject]@{
            Rules = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($IdentityRef, $ace.ActiveDirectoryRights, $ace.AccessControlType, $ace.InheritanceType, $inheritedObjectType)
            Ensure = $ace.Ensure
        }
        $referenceObject += $rule
    }

    return $referenceObject
}

Function Compare-ActiveDirectoryAccessRule
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject[]]
        $Expected,

        [Parameter()]
        [System.DirectoryServices.ActiveDirectoryAccessRule[]]
        $Actual
    )

    $results = @()
    $toBeRemoved = @()
    $absentToBeRemoved = @()

    $presentRules = $Expected.Where({$_.Ensure -eq 'Present'}).Rules
    $absentRules = $Expected.Where({$_.Ensure -eq 'Absent'}).Rules
    foreach($referenceObject in $presentRules)
    {
        $match = $Actual.Where({
            $_.ActiveDirectoryRights -eq $referenceObject.ActiveDirectoryRights -and
            $_.AccessControlType -eq $referenceObject.AccessControlType -and
            $_.InheritanceType -eq $referenceObject.InheritanceType -and
            $_.InheritedObjectType -eq $referenceObject.InheritedObjectType -and
            $_.IdentityReference -eq $referenceObject.IdentityReference
        })
        if($match.Count -ge 1)
        {
            $results += [PSCustomObject]@{
                Rule = $referenceObject
                Match = $true
            }
        }
        else
        {
            $results += [PSCustomObject]@{
                Rule = $referenceObject
                Match = $false
            }
        }
    }

    foreach($referenceObject in $absentRules)
    {
        $match = $Actual.Where({
            $_.ActiveDirectoryRights -eq $referenceObject.ActiveDirectoryRights -and
            $_.AccessControlType -eq $referenceObject.AccessControlType -and
            $_.InheritanceType -eq $referenceObject.InheritanceType -and
            $_.InheritedObjectType -eq $referenceObject.InheritedObjectType -and
            $_.IdentityReference -eq $referenceObject.IdentityReference
        })
        if($match.Count -gt 0)
        {
            $absentToBeRemoved += [PSCustomObject]@{
                Rule = $referenceObject
            }
        }
    }

    foreach($referenceObject in $Actual)
    {
        $match = $Expected.Rules.Where({
            $_.ActiveDirectoryRights -eq $referenceObject.ActiveDirectoryRights -and
            $_.AccessControlType -eq $referenceObject.AccessControlType -and
            $_.InheritanceType -eq $referenceObject.InheritanceType -and
            $_.InheritedObjectType -eq $referenceObject.InheritedObjectType -and
            $_.IdentityReference -eq $referenceObject.IdentityReference
        })
        if($match.Count -eq 0)
        {
            $toBeRemoved += [PSCustomObject]@{
                Rule = $referenceObject
            }
        }
    }

    return [PSCustomObject]@{
        Rules = $results
        ToBeRemoved = $toBeRemoved
        Absent = $absentToBeRemoved
    }
}

function Assert-Module
{
    [CmdletBinding()]
    param
    (
        [Parameter()] [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName = 'ActiveDirectory'
    )

    if (-not (Get-Module -Name $ModuleName -ListAvailable))
    {
        $errorId = '{0}_ModuleNotFound' -f $ModuleName;
        $errorMessage = $localizedString.RoleNotFoundError -f $ModuleName;
        ThrowInvalidOperationError -ErrorId $errorId -ErrorMessage $errorMessage;
    }
} 

Function Get-SchemaIdGuid
{
    Param 
    (
        [Parameter()]
        [string]
        $ObjectName
    )

    if($ObjectName)
    {
        $value = Get-ADObject -filter {name -eq $ObjectName} -SearchBase (Get-ADRootDSE).schemaNamingContext -prop schemaIDGUID
        return [system.guid]$value.schemaIDGUID 
    }
    else
    {
        return [system.guid]"00000000-0000-0000-0000-000000000000"
    }
}

Function Get-SchemaObjectName
{
    Param 
    (
        [Parameter()]
        [guid]
        $SchemaIdGuid
    )

        $value = Get-ADObject -filter {schemaIDGUID  -eq $SchemaIdGuid} -SearchBase (Get-ADRootDSE).schemaNamingContext -prop schemaIDGUID
        return $value.name 
}
