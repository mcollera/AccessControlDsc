#requires -Version 4.0 -Modules Pester

#region Setup for tests

$DSCResourceName = 'ActiveDirectoryAccessEntry'

Import-Module "$($PSScriptRoot)\..\..\DSCResources\$($DSCResourceName)\$($DSCResourceName).psm1" -Force
Import-Module "$($PSScriptRoot)\..\..\DscResources\AccessControlResourceHelper\AccessControlResourceHelper.psm1" -Force
Import-Module (Join-Path -Path ($PSScriptRoot | Split-Path) -ChildPath 'TestHelper.psm1') -Force

#endregion

InModuleScope ActiveDirectoryAccessEntry {
    $DSCResourceName = 'ActiveDirectoryAccessEntry'
    Describe "$DSCResourceName\Get-TargetResource" {

        Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
        Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
        Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
        Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$name -eq 'ActiveDirectory'} -ModuleName $DSCResourceName

        Context "Should return current Access Rules" {
            Mock -CommandName Get-Acl -MockWith {
                $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
                $identity = Resolve-Identity -Identity "Everyone"
                $identityRef = [System.Security.Principal.NTAccount]::new($identity.Name)
                $activeDirectoryRights = @("Delete","ReadControl")

                foreach($right in $activeDirectoryRights)
                {
                    $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef, [System.DirectoryServices.ActiveDirectoryRights]::$right , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
                    $collection.AddRule($accessRule)
                }

                $acl = @{Access = $collection}
                return $acl
            } -ModuleName $DSCResourceName
        
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights GenericAll -InheritanceType All -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a"  -ObjectType "00000000-0000-0000-0000-000000000000" -Ensure Present

            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }

            $getResult = & "$($DSCResourceName)\Get-TargetResource" @contextParams

            It 'Should return Ensure set as empty' {
                [string]::IsNullOrWhiteSpace($getResult.AccessControlList.AccessControlEntry.Ensure) | Should Be $true
            }

            It 'Should return DistinguishedName' {
                $getResult.DistinguishedName | Should Be "DC=PowerStig,DC=Local"
            }

            It 'Should return Principal' {
                $getResult.AccessControlList.Principal | Should Be "Everyone"
            }

            It 'Should return AccessControlEntries' {
                $getResult.AccessControlList.AccessControlEntry.Count | Should Be 2
            }

            It 'Should return InheritanceType' {
                $getResult.AccessControlList.AccessControlEntry[0].InheritanceType | Should Be "SelfAndChildren"
            }

            It 'Should return AccessControlType' {
                $getResult.AccessControlList.AccessControlEntry[0].AccessControlType | Should Be "Allow"
            }
        }
        
        Context 'No permissions exist' {

            Mock -CommandName Get-Acl -MockWith {
                $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
                $acl = @{Access = $collection}
                return $acl
            } -ModuleName $DSCResourceName
        
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights GenericAll -InheritanceType All -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a"  -ObjectType "00000000-0000-0000-0000-000000000000" -Ensure Present
            
            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }

            $getResult = Get-TargetResource @contextParams

            It 'Should return Ensure set as empty' {
                [string]::IsNullOrEmpty($getResult.AccessControl.AccessControlEntry.Ensure) | Should Be $true
            }

            It 'Should return DistinguishedName' {
                $getResult.DistinguishedName | Should Be $contextParams.DistinguishedName
            }

            It 'Should return Principal' {
                $getResult.AccessControlList.Principal | Should Be "Everyone"
            }

            It 'Should return empty AccessControlEntry' {
                $getResult.AccessControlList.AccessControlEntry.Count | Should Be 0
            }
        }
    }

    Describe "$DSCResourceName\Test-TargetResource" {
        
        Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
        Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
        Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
        Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$name -eq 'ActiveDirectory'}-ModuleName $DSCResourceName 
        Mock -CommandName Get-DelegationRightsGuid -MockWith { return [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a" } -ModuleName $DSCResourceName
        Mock -CommandName Get-SchemaObjectName -MockWith { return "Pwd-Last-Set" } -ModuleName $DSCResourceName

        Mock -CommandName Get-Acl -MockWith {
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $identity = Resolve-Identity -Identity "Everyone"
            $identityRef = [System.Security.Principal.NTAccount]::new($identity.Name)
            $activeDirectoryRights = @("Delete","ReadControl")

            foreach($right in $activeDirectoryRights)
            {
                $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef, [System.DirectoryServices.ActiveDirectoryRights]::$right , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
                $collection.AddRule($accessRule)
            }

            $acl = @{Access = $collection}
            return $acl
        } -ModuleName $DSCResourceName

        Context "Permissions already exist with ForcePrincipal False" {
        
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present
    
            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }
    
            $testResult = & "$($DSCResourceName)\Test-TargetResource" @contextParams
    
            It 'Should return true' {
                $testResult | Should Be $true        
            }
        }  
        
        Context "Permissions dont exist with ForcePrincipal False" {
            
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present

            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }

            $testResult = & "$($DSCResourceName)\Test-TargetResource" @contextParams

            It 'Should return false' {
                $testResult | Should Be $false
            }
        }

        Context "Permissions dont exist with ForcePrincipal true" {
            
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present
    
            $contextParams = @{        
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl        
            }
    
            $testResult = & "$($DSCResourceName)\Test-TargetResource" @contextParams
    
            It 'Should return false' {
                $testResult | Should Be $false
            }
        }

        Context "Permissions dont exist with ForcePrincipal false" {
            
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present
    
            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }
    
            $testResult = & "$($DSCResourceName)\Test-TargetResource" @contextParams
    
            It 'Should return false' {
                $testResult | Should Be $false
            }
        
        }
    
        Context "Multiple permissions already exist with ForcePrincipal true and only one principal required" {
            
            $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present
    
            $contextParams = @{
                DistinguishedName = "DC=PowerStig,DC=Local"
                AccessControlList = $tempAcl
            }
    
            $testResult = & "$($DSCResourceName)\Test-TargetResource" @contextParams
    
            It 'Should return false' {        
                $testResult | Should Be $false
            }
        }
    }

    Describe "Helper Functions" {

        Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
        Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
        Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
        Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$name -eq 'ActiveDirectory'} -ModuleName $DSCResourceName
        Mock -CommandName Get-DelegationRightsGuid -MockWith { return [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a" } -ModuleName $DSCResourceName
        Mock -CommandName Get-SchemaObjectName -MockWith { return "Pwd-Last-Set" } -ModuleName $DSCResourceName

        $identity = Resolve-Identity -Identity "Everyone"
        $identityRef = [System.Security.Principal.NTAccount]::new($identity.Name)
        $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $tempAcl =  New-ActiveDirectoryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a"  -ObjectType "00000000-0000-0000-0000-000000000000" -Ensure Present

        Context "ConvertTo-ActiveDirectoryAccessRule" {
            
            $convertedAccessRule = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $tempAcl -IdentityRef $identityRef

            It 'Should return 1 rule' {
                $convertedAccessRule.Rules.Count | Should Be 1
            }

            It 'Should return a pscustomobject' {                
                $convertedAccessRule.GetType().Name | Should Be "PSCustomObject"
            }

            foreach($property in ($accessRule | Get-Member -MemberType Properties))
            {
                It "$($property.Name) should match" {
                    $accessRule.($property.Name) | Should Be $convertedAccessRule.Rules[0].($property.Name)
                }
            }
        }

        Context "Compare-ActiveDirectoryAccessRule with matching rules only" {
            
            $convertedAccessRule = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $tempAcl -IdentityRef $identityRef
            $compare = Compare-ActiveDirectoryAccessRule -Actual $accessRule -Expected $convertedAccessRule

            It 'Should return a pscustomobject' {
                $convertedAccessRule.GetType().Name | Should Be "PSCustomObject"
            }

            It "Should not have any ToBeRemoved Rules" {
                $compare.ToBeRemoved.Count | Should Be 0
            }

            It "Should not have any Absent Rules" {
                $compare.Absent.Count | Should Be 0
            }

            It "Should have 1 Rule" {
                $compare.Rules.Count | Should Be 1
            }

            It "Returned rule should Match" {
                $compare.Rules.Match | Should Be "True"
            }
        }

        Context "Compare-ActiveDirectoryAccessRule with multiple rules and Expected rule existing" {
            
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $identity = Resolve-Identity -Identity "Everyone"
            $identityRef = [System.Security.Principal.NTAccount]::new($identity.Name)
            $identityRef2 = [System.Security.Principal.NTAccount]::new("BUILTIN\Users")
            $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $accessRule2 = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef, [System.DirectoryServices.ActiveDirectoryRights]::ReadControl , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $accessRule3 = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($identityRef2, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AccessControlType]::Allow, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $collection.AddRule($accessRule)
            $collection.AddRule($accessRule2)
            $collection.AddRule($accessRule3)
            $acl = @{Access = $collection}

            $convertedAccessRule = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $tempAcl -IdentityRef $identityRef
            $compare = Compare-ActiveDirectoryAccessRule -Actual $acl.Access -Expected $convertedAccessRule

            It 'Should return a pscustomobject' {
                $convertedAccessRule.GetType().Name | Should Be "PSCustomObject"
            }

            It "Should not have any ToBeRemoved Rules" {
                $compare.ToBeRemoved.Count | Should Be 2
            }

            It "Should not have any Absent Rules" {
                $compare.Absent.Count | Should Be 0
            }

            It "Should have 1 Rule" {
                $compare.Rules.Count | Should Be 1
            }

            It "Returned rule should Match" {
                $compare.Rules.Match | Should Be "True"
            }
        }

        Context "Compare-ActiveDirectoryAccessRule with multiple rules and Expected not existing existing" {
            
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $identity = Resolve-Identity -Identity "Everyone"
            $identityRefs = @([System.Security.Principal.NTAccount]::new($identity.Name),[System.Security.Principal.NTAccount]::new("BUILTIN\Users"))

            foreach($ref in $identityRefs)
            {
                $accessRule = [System.DirectoryServices.ActiveDirectoryAccessRule]::new($ref, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AccessControlType]::Deny, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
                $collection.AddRule($accessRule)
            }

            $acl = @{Access = $collection}

            $convertedAccessRule = ConvertTo-ActiveDirectoryAccessRule -AccessControlList $tempAcl -IdentityRef $identityRef
            $compare = Compare-ActiveDirectoryAccessRule -Actual $acl.Access -Expected $convertedAccessRule

            It 'Should return a pscustomobject' {
                $convertedAccessRule.GetType().Name | Should Be "PSCustomObject"
            }

            It "Should not have any ToBeRemoved Rules" {
                $compare.ToBeRemoved.Count | Should Be 2
            }

            It "Should not have any Absent Rules" {
                $compare.Absent.Count | Should Be 0
            }

            It "Should have 1 Rule" {
                $compare.Rules.Count | Should Be 1
            }

            It "Returned rule should Match" {
                $compare.Rules.Match | Should Be "False"
            }
        }
    }        
}
