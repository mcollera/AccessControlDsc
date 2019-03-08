#requires -Version 4.0 -Modules Pester

#region Setup for tests

$DSCResourceName = 'ActiveDirectoryAuditRuleEntry'

Import-Module "$($PSScriptRoot)\..\..\DSCResources\$($DSCResourceName)\$($DSCResourceName).psm1" -Force
Import-Module "$($PSScriptRoot)\..\..\DscResources\AccessControlResourceHelper\AccessControlResourceHelper.psm1" -Force
Import-Module "$($PSScriptRoot)\..\TestHelper.psm1" -Force

#endregion

$DSCResourceName = 'ActiveDirectoryAuditRuleEntry'
Describe "$DSCResourceName\Get-TargetResource" {

    Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
    Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
    Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
    Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$Name -eq 'ActiveDirectory'} -ModuleName $DSCResourceName

    Context "Should return current Audit Rules" {
        Mock -CommandName Get-Acl -MockWith {
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $Identity = Resolve-Identity -Identity "Everyone"
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
            $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Success, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $auditRule2 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $collection.AddRule($auditRule)
            $collection.AddRule($auditRule2)
            $acl = @{Audit = $collection}
            return $acl
        } -ModuleName $DSCResourceName

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights GenericAll -InheritanceType All -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $GetResult = & "$($DSCResourceName)\Get-TargetResource" @ContextParams

        It 'Should return Ensure set as empty' {
            [string]::IsNullOrWhiteSpace($GetResult.AccessControlList.AccessControlEntry.Ensure) | Should Be $true
        }

        It "Should return $false from GetReturn.Force" {
            $GetResult.Force | Should Be $false
        }

        It 'Should return DistinguishedName' {
            $GetResult.DistinguishedName | Should Be "DC=PowerStig,DC=Local"
        }

        It 'Should return Principal' {
            $GetResult.AccessControlList.Principal | Should Be "Everyone"
        }

        It 'Should return AccessControlEntries' {
            $GetResult.AccessControlList.AccessControlEntry.Count | Should Be 2
        }

        It 'Should return InheritanceType' {
            $GetResult.AccessControlList.AccessControlEntry[0].InheritanceType | Should Be "SelfAndChildren"
        }

        It 'Should return AuditFlags' {
            $GetResult.AccessControlList.AccessControlEntry[0].AuditFlags | Should Be "Success"
        }
    }

    Context 'No permissions exist' {

        Mock -CommandName Get-Acl -MockWith {
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $acl = @{Audit = $collection}
            return $acl
        } -ModuleName $DSCResourceName

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights GenericAll -InheritanceType All -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $GetResult = Get-TargetResource @ContextParams

        It 'Should return Ensure set as empty' {
            [string]::IsNullOrEmpty($GetResult.AccessControl.AccessControlEntry.Ensure) | Should Be $true
        }

        It 'Should return DistinguishedName' {
            $GetResult.DistinguishedName | Should Be $ContextParams.DistinguishedName
        }

        It 'Should return Principal' {
            $GetResult.AccessControlList.Principal | Should Be "Everyone"
        }

        It 'Should return empty AccessControlInformation' {
            $GetResult.AccessControlList.AccessControlEntry.Count | Should Be 0
        }
    }
}

Describe "$DSCResourceName\Test-TargetResource" {

    Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
    Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
    Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
    Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$Name -eq 'ActiveDirectory'} -ModuleName $DSCResourceName
    Mock -CommandName Get-DelegationRightsGuid -MockWith { return [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a" } -ModuleName $DSCResourceName
    Mock -CommandName Get-SchemaObjectName -MockWith { return "Pwd-Last-Set" } -ModuleName $DSCResourceName
    Mock -CommandName Write-CustomVerboseMessage -MockWith {} -ModuleName $DSCResourceName

    Mock -CommandName Get-Acl -MockWith {
        $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
        $Identity = Resolve-Identity -Identity "Everyone"
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $IdentityRef2 = [System.Security.Principal.NTAccount]::new("BUILTIN\Users")
        $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Success, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $auditRule2 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $auditRule3 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef2, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $collection.AddRule($auditRule)
        $collection.AddRule($auditRule2)
        $collection.AddRule($auditRule3)
        $acl = @{Audit = $collection}
        return $acl
    } -ModuleName $DSCResourceName

    Context "Permissions already exist with ForcePrincipal False" {

        $TempAcl = New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType '52ea1a9a-be7e-4213-9e69-5f28cb89b56a' -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return true' {
            $TestResult | Should Be $true
        }
    }

    Context "Permissions dont exist with ForcePrincipal False" {

        $TempAcl = New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return false' {
            $TestResult | Should Be $false
        }
    }

    Context "Permissions dont exist with ForcePrincipal true" {

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $true -AuditFlags Success -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return false' {
            $TestResult | Should Be $false
        }
    }

    Context "Permissions dont exist with ForcePrincipal false" {

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights CreateChild -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return false' {
            $TestResult | Should Be $false
        }

    }

    Context "Multiple permissions already exist with ForcePrincipal true and only one principal required" {

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $true -AuditFlags Success -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return false' {
            $TestResult | Should Be $false
        }
    }

    Context "Multiple user principals exist with Force true" {

        $TempAcl =  New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            Force = $true
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return false' {
            $TestResult | Should Be $false
        }
    }

    Context "Only requested permissions exist with Force true" {

        Mock -CommandName Get-Acl -MockWith {
            $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
            $Identity = Resolve-Identity -Identity "Everyone"
            $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
            $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Success, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
            $collection.AddRule($auditRule)
            $acl = @{Audit = $collection}
            return $acl
        } -ModuleName $DSCResourceName

        $TempAcl = New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

        $ContextParams = @{
            DistinguishedName = "DC=PowerStig,DC=Local"
            Force = $true
            AccessControlList = $TempAcl
        }

        $TestResult = & "$($DSCResourceName)\Test-TargetResource" @ContextParams

        It 'Should return true' {
            $TestResult | Should Be $true
        }
    }
}

Describe "Helper Functions" {

    Mock -CommandName Join-Path -MockWith { return "AD:\DC=PowerStig,DC=Local" } -ModuleName $DSCResourceName
    Mock -CommandName Test-Path -MockWith { return $true } -ModuleName $DSCResourceName
    Mock -CommandName Assert-Module -MockWith {} -ModuleName $DSCResourceName
    Mock -CommandName Import-Module -MockWith {} -ParameterFilter {$Name -eq 'ActiveDirectory'} -ModuleName $DSCResourceName
    Mock -CommandName Get-DelegationRightsGuid -MockWith { return [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a" } -ModuleName $DSCResourceName
    Mock -CommandName Get-SchemaObjectName -MockWith { return "Pwd-Last-Set" } -ModuleName $DSCResourceName
    Mock -CommandName Write-CustomVerboseMessage -MockWith {} -ModuleName $DSCResourceName

    $Identity = Resolve-Identity -Identity "Everyone"
    $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
    $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Success, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
    $TempAcl = New-AuditAccessControlList -Principal "Everyone" -ForcePrincipal $false -AuditFlags Success -ActiveDirectoryRights Delete -InheritanceType SelfAndChildren -InheritedObjectType "52ea1a9a-be7e-4213-9e69-5f28cb89b56a" -ObjectType 'f30e3bbf-9ff0-11d1-b603-0000f80367c1' -Ensure Present

    Context "ConvertTo-ActiveDirectoryAuditRule" {

        $ConvertedAuditRule = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $TempAcl -IdentityRef $IdentityRef

        It 'Should return 1 rule' {
            $ConvertedAuditRule.Rules.Count | Should Be 1
        }

        It 'Should return a pscustomobject' {
            $ConvertedAuditRule.GetType().Name | Should Be "PSCustomObject"
        }

        foreach($property in ($auditRule | Get-Member -MemberType Properties))
        {
            It "$($property.Name) should match" {
                $auditRule.($property.Name) -eq $ConvertedAuditRule.Rules[0].($property.Name) | Should Be $true
            }
        }
    }

    Context "Compare-ActiveDirectoryAuditRule with matching rules only" {

        $ConvertedAuditRule = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        $compare = Compare-ActiveDirectoryAuditRule -Actual $auditRule -Expected $ConvertedAuditRule

        It 'Should return a pscustomobject' {
            $ConvertedAuditRule.GetType().Name | Should Be "PSCustomObject"
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

    Context "Compare-ActiveDirectoryAuditRule with multiple rules and Expected rule existing" {

        $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
        $Identity = Resolve-Identity -Identity "Everyone"
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $IdentityRef2 = [System.Security.Principal.NTAccount]::new("BUILTIN\Users")
        $auditRule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Success, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $auditRule2 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $auditRule3 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef2, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $collection.AddRule($auditRule)
        $collection.AddRule($auditRule2)
        $collection.AddRule($auditRule3)
        $acl = @{Audit = $collection}

        $ConvertedAuditRule = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        $compare = Compare-ActiveDirectoryAuditRule -Actual $acl.Audit -Expected $ConvertedAuditRule

        It 'Should return a pscustomobject' {
            $ConvertedAuditRule.GetType().Name | Should Be "PSCustomObject"
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

    Context "Compare-ActiveDirectoryAuditRule with multiple rules and Expected not existing existing" {

        $collection = [System.Security.AccessControl.AuthorizationRuleCollection]::new()
        $Identity = Resolve-Identity -Identity "Everyone"
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $IdentityRef2 = [System.Security.Principal.NTAccount]::new("BUILTIN\Users")
        $auditRule2 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $auditRule3 = [System.DirectoryServices.ActiveDirectoryAuditRule]::new($IdentityRef2, [System.DirectoryServices.ActiveDirectoryRights]::Delete , [System.Security.AccessControl.AuditFlags]::Failure, ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit,[System.Security.AccessControl.InheritanceFlags]::ObjectInherit) , [guid]"52ea1a9a-be7e-4213-9e69-5f28cb89b56a")
        $collection.AddRule($auditRule2)
        $collection.AddRule($auditRule3)
        $acl = @{Audit = $collection}

        $ConvertedAuditRule = ConvertTo-ActiveDirectoryAuditRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        $compare = Compare-ActiveDirectoryAuditRule -Actual $acl.Audit -Expected $ConvertedAuditRule

        It 'Should return a pscustomobject' {
            $ConvertedAuditRule.GetType().Name | Should Be "PSCustomObject"
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
