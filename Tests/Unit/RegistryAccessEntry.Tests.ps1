﻿#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

#region Setup for tests
$Global:DSCModuleName = 'AccessControlDsc'
$Global:DSCResourceName = 'RegistryAccessEntry'

Import-Module "$($PSScriptRoot)\..\..\DSCResources\$($Global:DSCResourceName)\$($Global:DSCResourceName).psm1" -Force
Import-Module "$($PSScriptRoot)\..\TestHelper.psm1" -Force
Import-Module Pester -Force
#endregion

Describe "$Global:DSCResourceName\Get-TargetResource" {
    Context "Permissions should exist" {
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $pathName = "HKCU:\TestKey"
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
            -ArgumentList @(
                $TempAcl.Principal,
                'Notify',
                'ContainerInherit',
                'None',
                'Allow'
            )
        
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
            -ArgumentList @(
                $TempAcl.Principal,
                'FullControl',
                'None',
                'None',
                'Allow'
            )            
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        $GetResult = & "$($Global:DSCResourceName)\Get-TargetResource" @ContextParams

        It 'Should return Ensure set as empty' {
            $GetResult.AccessControl.AccessControlEntry.Ensure | Should Be $null
        }
                    
        It "Should return $false from GetReturn.Force" {
            $GetResult.Force | Should Be $false
        }
        
        It 'Should return Path' {
            $GetResult.Path | Should Be $ContextParams.Path
        }
        
        It 'Should return Principal' {
            $GetResult.Principal | Should Be $ContextParams.Principal
        }
        
        It 'Should return AccessControlEntries' {
            $GetResult.AccessControlList.AccessControlEntry.Count | Should Be $TempAccessRules.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'No permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempRegKeyAcl -Path $PathName 

        $GetResult = Get-TargetResource @ContextParams

        It 'Should return Ensure set as empty' {
            $GetResult.AccessControl.AccessControlEntry.Ensure | Should Be $null
        }

        It 'Should return Path' {
            $GetResult.Path | Should Be $ContextParams.Path
        }

        It 'Should return Principal' {
            $GetResult.Principal | Should Be $ContextParams.Principal
        }

        It 'Should return empty AccessControlInformation' {
            $GetResult.AccessControlInformation.Count | Should Be 0
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\Test-TargetResource behavior with Ensure set to Absent" {
    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempRegKeyAcl -Path $PathName 
        
        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }
    }

    Context 'AccessControlInformation is specified, no matching permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'QueryValues',
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateSubkey', 'CreateLink'),
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, matching permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'FullControl',
                    'None',
                    'None',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is not specified' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
    
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'ContainerInherit',
                    'None',
                    'Allow'
                )
    
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'FullControl',
                    'None',
                    'None',
                    'Allow'
                )
    
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'TakeOwnership',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )
    
        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Throw When Test-TargetResource is run' {
            
            { Test-TargetResource @ContextParams }| Should Throw
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\Test-TargetResource behavior with Ensure set to Present" {
    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'KeySubkeys' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempRegKeyAcl -Path $PathName
        
        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist and ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $True -AccessControlType Allow -RegistryRights @('CreateLink', 'CreateSubkey') -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, correct permissions exist and ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $True -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Subkeys' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
               -ArgumentList @(
                   $TempAcl.Principal,
                   'FullControl',
                   'ContainerInherit',
                   'InheritOnly',
                   'Allow'
               )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist and ForcePrincipal is set to false' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights @('CreateLink', 'CreateSubkey') -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is not specified' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
    
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )
    
        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Throw When Test-TargetResource is run' {
            
            { Test-TargetResource @ContextParams }| Should Throw
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\Set-TargetResource behavior with Ensure set to Absent" {
    Context 'AccessControlInformation is not specified' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )
        
        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Throw When Set-TargetResource is run' {
            
            { Set-TargetResource @ContextParams }| Should Throw
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, matching permissions exist, ForcePrincipal is set to false' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights EnumerateSubKeys -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should remove matching permissions' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $TempAcl.Principal}
            ).Count | 
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be ($TempAccessRules.Count - $ContextParams.AccessControlList.AccessControlEntry.Count)
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, no matching permissions exist, ForcePrincipal is set to false' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'KeySubKeys' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should not change any of the permissions' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $TempAcl.Principal}
            ).Count | 
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $true

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be ($TempAccessRules.Count)
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, matching permissions exist, ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'FullControl',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Remove Principal from Access Control List' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $TempAcl.Principal}
            ).Count | 
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be 0
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, no matching permissions exist, ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Remove Principal from Access Control List' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $TempAcl.Principal}
            ).Count | 
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be 0
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\Set-TargetResource behavior with Ensure set to Present" {
    Context 'AccessControlInformation is not specified' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
    
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )
    
        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Throw When Set-TargetResource is run' {
            
            { Set-TargetResource @ContextParams }| Should Throw
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempRegKeyAcl -Path $PathName
        
        It 'Should add the desired permissions' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be 0

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $ContextParams.AccessControlList.AccessControlEntry.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist, ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $True -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Subkeys' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateLink', 'CreateSubkey', 'Delete'),
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'FullControl',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should remove other permissions' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $ContextParams.AccessControlList.AccessControlEntry.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist, ForcePrincipal is set to false' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights CreateSubkey -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ChangePermissions',
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should Keep all the permissions' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $true

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $TempAccessRules.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions do not exist, other permissions exist, ForcePrincipal is set to true' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ChangePermissions',
                    'ContainerInherit',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should remove other permissions and add Desired Access Control Entry' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).RegistryRights |
            Should Be "FullControl"
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context 'AccessControlInformation is specified, desired permissions do not exist, other permissions exist, ForcePrincipal is set to false' {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights Delete -Inheritance 'KeySubKeys' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ChangePermissions',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'EnumerateSubKeys',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        It 'Should add Desired Access Control Entry and leave existing Entries' {

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be $TempAccessRules.Count

            Test-TargetResource @ContextParams | Should Be $false

            Set-TargetResource @ContextParams

            Test-TargetResource @ContextParams | Should Be $true

            (Get-Acl -Path $ContextParams.Path).Access.Where(
                {$_.IsInherited -eq $false -and $_.IdentityReference -eq $ContextParams.AccessControlList.Principal}
            ).Count |
            Should Be ($TempAccessRules.Count + $ContextParams.AccessControlList.AccessControlEntry.Count)
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\Get-RegistryRuleInheritenceFlags" {
    Context "Inheritance Names" {
        It "Should return 0-0" {
            $InheritanceFlags = Get-RegistryRuleInheritenceFlags -Inheritance "Key"

            $InheritanceFlags.InheritanceFlag | Should be 0
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 1-0" {
            $InheritanceFlags = Get-RegistryRuleInheritenceFlags -Inheritance "KeySubkeys"

            $InheritanceFlags.InheritanceFlag | Should be 1
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 1-2" {
            $InheritanceFlags = Get-RegistryRuleInheritenceFlags -Inheritance "Subkeys"

            $InheritanceFlags.InheritanceFlag | Should be 1
            $InheritanceFlags.PropagationFlag | Should be 2
        }

        It "Should return null when abnormal Inheritance is passed" {
            $InheritanceFlags = Get-RegistryRuleInheritenceFlags -Inheritance "The files are 'in' the computer."

            $InheritanceFlags.InheritanceFlag | Should be $null
            $InheritanceFlags.PropagationFlag | Should be $null
        }
    }
}

Describe "$Global:DSCResourceName\Get-RegistryRuleInheritenceName" {
    Context "Inheritance and Propagation Flags" {
        It "Should return Key" {
            $InheritanceName = Get-RegistryRuleInheritenceName -InheritanceFlag 0 -PropagationFlag 0
    
            $InheritanceName | Should be "This Key Only"
        }
    
        It "Should return KeySubkeys" {
            $InheritanceName = Get-RegistryRuleInheritenceName -InheritanceFlag 1 -PropagationFlag 0
    
            $InheritanceName | Should be "This Key and Subkeys"
        }
    
        It "Should return Subkeys" {
            $InheritanceName = Get-RegistryRuleInheritenceName -InheritanceFlag 1 -PropagationFlag 2
    
            $InheritanceName | Should be "Subkeys Only"
        }
    
        It "Should return none if abnormal Inheritance and Propagation Flags are passed" {
            $InheritanceName = Get-RegistryRuleInheritenceName -InheritanceFlag 4 -PropagationFlag 4
    
            $InheritanceName | Should be "none"
        }
    }
}

Describe "$Global:DSCResourceName\ConvertTo-RegistryAccessRule" {
    Context "Should convert to a valid Registry Key Access Rule" {
        It "Should return a FilseSystemAccessRule Object" {
            $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Absent 
            $FileSystemAccessRule = ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $TempAcl.Principal
    
           $FileSystemAccessRule.Rules | Should BeOfType System.Security.AccessControl.RegistryAccessRule
        }
    
        It "Should return expected values" {
            $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights FullControl -Inheritance 'Key' -Ensure Present
            $FileSystemAccessRule = ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $TempAcl.Principal
    
            $FileSystemAccessRule.Rules.RegistryRights | Should Be "FullControl"
            $FileSystemAccessRule.Rules.AccessControlType | Should Be "Allow"
            $FileSystemAccessRule.Rules.IdentityReference | Should Be "Everyone"
            $FileSystemAccessRule.Rules.IsInherited | Should Be "False"
            $FileSystemAccessRule.Rules.InheritanceFlags | Should Be "None"
            $FileSystemAccessRule.Rules.PropagationFlags | Should Be "None"
        }
    }
}

Describe "$Global:DSCResourceName\Compare-RegistryRules" {
    Context "Compare-RegistryRules with Ensure set to Absent with no matching rules" {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights EnumerateSubKeys -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl 
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        
        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should not have any Rules to be removed" {
            $testComparison = Compare-RegistryRules -Expected $ACLRules -Actual $actualAce

            $testComparison.ToBeRemoved.Rule.Count | Should be $actualAce.Count
            $testComparison.Absent | Should Be $null
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context "Compare-NtfsRules with Ensure set to Absent with matching rules" {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights Delete -Inheritance 'Key' -Ensure Absent 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl 
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'CreateSubkey',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        
        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should have matching rule to be removed" {
            $testComparison = Compare-RegistryRules -Expected $ACLRules -Actual $actualAce

            $testComparison.ToBeRemoved.Rule.Count | Should be ($actualAce.Count - $TempAcl.AccessControlEntry.Count) 
            $testComparison.Absent.Count | Should Be $TempAcl.AccessControlEntry.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context "Compare-NtfsRules with Ensure set to Present with no matching rules" {
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights CreateSubkey -Inheritance 'KeySubKeys' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl 
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ChangePermissions',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        
        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should have new rule to add" {
            $testComparison = Compare-RegistryRules -Expected $ACLRules -Actual $actualAce 

            $testComparison.ToBeRemoved.Rule.Count | Should be $TempAccessRules.Count
            $testComparison.Rules.Count | Should be $TempAcl.AccessControlEntry.Count
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }

    Context "Compare-NtfsRules with matching rules and Ensure set to Present" { 
        $pathName = "HKCU:\TestKey"
        $TempAcl = New-RegistryAccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -RegistryRights Delete -Inheritance 'Key' -Ensure Present 
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl 
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Delete',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.RegistryAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ChangePermissions',
                    'ContainerInherit',
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempRegKeyAcl -Path $PathName -AccessRulesToAdd $TempAccessRules 
        
        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-RegistryAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef
        
        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should return matching rules" {
            $testComparison = Compare-RegistryRules -Expected $ACLRules -Actual $actualAce

            $testComparison.ToBeRemoved.Rule.Count | Should be ($TempAccessRules.Count - $TempAcl.AccessControlEntry.Count)
            $testComparison.Rules.Count | Should be $TempAcl.AccessControlEntry.Count
            $testComparison.Rules.Match | Should be $true
        }

        if ($false -ne (Test-Path $pathName))
        {
            Remove-Item -Path $pathName
        }
    }
}

Describe "$Global:DSCResourceName\ResourceHelper\Resolve-Identity" {
    Context "Resolve Username" {
        It "Should resolve when input is a username" {
            $Identity = Resolve-Identity -Identity "Local"

            $Identity.Name | Should be "LOCAL"
            $Identity.SID | Should be "S-1-2-0"
        }
    
        It "Should resolve when input is an SID" {
            $Identity = Resolve-Identity -Identity "S-1-2-0"

            $Identity.Name | Should be "LOCAL"
            $Identity.SID | Should be "S-1-2-0"
        }
    }

    Context "Username does not exist." {

        It "Should fail when it cannot resolve a username" {

           { Resolve-Identity -Identity "Anorak"  -ErrorAction Stop} | Should Throw
        }
    }
}

Describe "$Global:DSCResourceName\ResourceHelper\ConvertTo-SID" {
    Context "Identity will contain a '\' e.g. BUILTIN\Users" {
        It "Should return a proper SID" {
            $SID = ConvertTo-SID -IdentityReference "BUILTIN\Users"

            $SID.Value | Should be "S-1-5-32-545"
        } 
    }
}
