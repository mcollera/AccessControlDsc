#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

#region Setup for tests
$DSCResourceName = 'NTFSAccessEntry'

Import-Module "$($PSScriptRoot)\..\..\DSCResources\$($DSCResourceName)\$($DSCResourceName).psm1" -Force
Import-Module "$($PSScriptRoot)\..\TestHelper.psm1" -Force

#endregion

Describe "$DSCResourceName\Get-TargetResource" {
    Context "Permissions should exist" {
        $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -FileSystemRights FullControl -Inheritance 'This Folder and Files' -Ensure Absent
        $pathName = "$TestDrive\TestDirectory"
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList @(
                $TempAcl.Principal,
                'ReadAndExecute',
                @('ContainerInherit', 'ObjectInherit'),
                'None',
                'Allow'
            )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList @(
                $TempAcl.Principal,
                'Modify',
                'None',
                'None',
                'Allow'
            )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
            -ArgumentList @(
                $TempAcl.Principal,
                @('CreateFiles', 'AppendData'),
                @('ContainerInherit', 'ObjectInherit'),
                'InheritOnly',
                'Allow'
            )
        )

        Set-NewTempItemAcl -Path $PathName -AccessRulesToAdd $TempAccessRules -PassThru
        $GetResult = & "$($DSCResourceName)\Get-TargetResource" @ContextParams

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
            $GetResult.AccessControlList.AccessControlEntry.Count | Should Be 3
        }
    }

    Context 'No permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'BUILTIN\Users' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights FullControl -Inheritance 'This Folder and Files' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

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
    }
}

Describe "$DSCResourceName\Test-TargetResource behavior with Ensure set to Absent" {
    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights ChangePermissions -Inheritance 'This Folder and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }
    }

    Context 'AccessControlInformation is specified, no matching permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Deny -FileSystemRights ChangePermissions -Inheritance 'This Folder and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }
    }

    Context 'AccessControlInformation is specified, matching permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights Modify -Inheritance 'This Folder Only' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }
    }

    Context 'AccessControlInformation is not specified' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should Throw When Test-TargetResource is run' {

            { Test-TargetResource @ContextParams }| Should Throw
        }
    }
}

Describe "$DSCResourceName\Test-TargetResource behavior with Ensure set to Present" {
    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights ReadAndExecute -Inheritance 'Subfolders and Files Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights ReadAndExecute -Inheritance 'This Folder Subfolders and Files' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should return False' {
            Test-TargetResource @ContextParams | Should Be $false
        }
    }

    Context 'AccessControlInformation is specified, permissions exist and match the desired state' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights @("CreateFiles", "AppendData") -Inheritance 'Subfolders and Files Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
               -ArgumentList @(
                   $TempAcl.Principal,
                   @('CreateFiles', 'AppendData'),
                   @('ContainerInherit', 'ObjectInherit'),
                   'InheritOnly',
                   'Allow'
               )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should return True' {
            Test-TargetResource @ContextParams | Should Be $true
        }
    }

    Context 'AccessControlInformation is not specified' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should Throw When Test-TargetResource is run' {

            { Test-TargetResource @ContextParams }| Should Throw
        }
    }
}

Describe "$DSCResourceName\Set-TargetResource behavior with Ensure set to Absent" {
    Context 'AccessControlInformation is not specified' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should Throw When Set-TargetResource is run' {

            { Set-TargetResource @ContextParams }| Should Throw
        }
    }

    Context 'AccessControlInformation is specified, matching permissions exist, ForcePrincipal is set to false' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights ReadAndExecute -Inheritance 'This Folder Subfolders and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )

        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }

    Context 'AccessControlInformation is specified, no matching permissions exist, ForcePrincipal is set to false' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights DeleteSubdirectoriesAndFiles -Inheritance 'This Folder Subfolders and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }

    Context 'AccessControlInformation is specified, matching permissions exist, ForcePrincipal is set to true' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights ReadAndExecute -Inheritance 'This Folder Subfolders and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }

    Context 'AccessControlInformation is specified, no matching permissions exist, ForcePrincipal is set to true' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights Modify -Inheritance 'This Folder Only' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }
}

Describe "$DSCResourceName\Set-TargetResource behavior with Ensure set to Present" {
    Context 'AccessControlInformation is not specified' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        It 'Should Throw When Set-TargetResource is run' {

            { Set-TargetResource @ContextParams }| Should Throw
        }
    }

    Context 'AccessControlInformation is specified, no permissions exist' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights ReadAndExecute -Inheritance 'This Folder Subfolders and Files' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path

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
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist, ForcePrincipal is set to true' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights 'Modify' -Inheritance 'This Folder Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }

    Context 'AccessControlInformation is specified, desired permissions exist, other permissions exist, ForcePrincipal is set to false' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights 'Modify' -Inheritance 'This Folder Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }
        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }

    Context 'AccessControlInformation is specified, desired permissions do not exist, other permissions exist, ForcePrincipal is set to true' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $true -AccessControlType Allow -FileSystemRights 'Modify' -Inheritance 'This Folder Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
            ).FileSystemRights |
            Should Be "Modify, Synchronize"
        }
    }

    Context 'AccessControlInformation is specified, desired permissions do not exist, other permissions exist, ForcePrincipal is set to false' {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal 'Everyone' -ForcePrincipal $false -AccessControlType Allow -FileSystemRights 'Modify' -Inheritance 'This Folder Only' -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

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
    }
}

Describe "$DSCResourceName\Get-NtfsInheritenceFlag" {
    Context "Inheritance Names" {
        It "Should return 0-0" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "This folder only"

            $InheritanceFlags.InheritanceFlag | Should be 0
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 3-0" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "This folder subfolders and files"

            $InheritanceFlags.InheritanceFlag | Should be 3
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 1-0" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "This folder and subfolders"

            $InheritanceFlags.InheritanceFlag | Should be 1
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 2-0" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "This folder and files"

            $InheritanceFlags.InheritanceFlag | Should be 2
            $InheritanceFlags.PropagationFlag | Should be 0
        }

        It "Should return 3-2" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "Subfolders and files only"

            $InheritanceFlags.InheritanceFlag | Should be 3
            $InheritanceFlags.PropagationFlag | Should be 2
        }

        It "Should return 1-2" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "Subfolders only"

            $InheritanceFlags.InheritanceFlag | Should be 1
            $InheritanceFlags.PropagationFlag | Should be 2
        }

        It "Should return 2-2" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "Files only"

            $InheritanceFlags.InheritanceFlag | Should be 2
            $InheritanceFlags.PropagationFlag | Should be 2
        }

        It "Should return null when abnormal Inheritance is passed" {
            $InheritanceFlags = Get-NtfsInheritenceFlag -Inheritance "The files are 'in' the computer."

            $InheritanceFlags.InheritanceFlag | Should be $null
            $InheritanceFlags.PropagationFlag | Should be $null
        }
    }
}

Describe "$DSCResourceName\Get-NtfsInheritenceName" {
    Context "Inheritance and Propagation Flags" {
        It "Should return This folder only" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 0 -PropagationFlag 0

            $InheritanceName | Should be "This folder only"
        }

        It "Should return This folder subfolders and files" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 3 -PropagationFlag 0

            $InheritanceName | Should be "This folder subfolders and files"
        }

        It "Should return This folder and subfolders" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 1 -PropagationFlag 0

            $InheritanceName | Should be "This folder and subfolders"
        }

        It "Should return This folder and files" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 2 -PropagationFlag 0

            $InheritanceName | Should be "This folder and files"
        }

        It "Should return Subfolders and files only" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 3 -PropagationFlag 2

            $InheritanceName | Should be "Subfolders and files only"
        }

        It "Should return Subfolders Only" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 1 -PropagationFlag 2

            $InheritanceName | Should be "Subfolders Only"
        }

        It "Should return Files Only" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 2 -PropagationFlag 2

            $InheritanceName | Should be "Files Only"
        }

        It "Should return none if abnormal Inheritance and Propagation Flags are passed" {
            $InheritanceName = Get-NtfsInheritenceName -InheritanceFlag 4 -PropagationFlag 4

            $InheritanceName | Should be "none"
        }
    }
}

Describe "$DSCResourceName\ConvertTo-FileSystemAccessRule" {
    Context "Should convert to a valid File System Access Rule" {
        It "Should return a FilseSystemAccessRule Object" {
           $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -FileSystemRights FullControl -Inheritance 'This Folder and Files' -Ensure Absent
           $FileSystemAccessRule = ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $TempAcl.Principal

           $FileSystemAccessRule.Rules | Should BeOfType System.Security.AccessControl.FileSystemAccessRule
        }

        It "Should return expected values" {
            $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -FileSystemRights FullControl -Inheritance 'This Folder and Files' -Ensure Present
            $FileSystemAccessRule = ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $TempAcl.Principal

            $FileSystemAccessRule.Rules.FileSystemRights | Should Be "FullControl"
            $FileSystemAccessRule.Rules.AccessControlType | Should Be "Allow"
            $FileSystemAccessRule.Rules.IdentityReference | Should Be "Everyone"
            $FileSystemAccessRule.Rules.IsInherited | Should Be "False"
            $FileSystemAccessRule.Rules.InheritanceFlags | Should Be "ObjectInherit"
            $FileSystemAccessRule.Rules.PropagationFlags | Should Be "None"
        }
    }
}

Describe "$DSCResourceName\Compare-NtfsRule" {
    Context "Compare-NtfsRule with Ensure set to Absent with no matching rules" {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -FileSystemRights FullControl -Inheritance 'This Folder and Files' -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef

        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should not have any Rules to be removed" {
            $testComparison = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $TempAcl.ForcePrincipal

            $testComparison.ToBeRemoved.Rule.Count | Should be $actualAce.Count
            $testComparison.Absent | Should Be $null
        }
    }

    Context "Compare-NtfsRule with Ensure set to Absent with matching rules" {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -FileSystemRights "ReadAndExecute" -Inheritance "This folder subfolders and files" -Ensure Absent
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'ReadAndExecute',
                    @('ContainerInherit', 'ObjectInherit'),
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef

        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should have matching rule to be removed" {
            $testComparison = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $TempAcl.ForcePrincipal

            $testComparison.ToBeRemoved.Rule.Count | Should be ($actualAce.Count - $TempAcl.AccessControlEntry.Count)
            $testComparison.Absent.Count | Should Be $TempAcl.AccessControlEntry.Count
        }
    }

    Context "Compare-NtfsRule with Ensure set to Present with no matching rules" {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $true -AccessControlType Allow -FileSystemRights "ReadAndExecute" -Inheritance "This folder subfolders and files" -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef

        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should have new rule to add" {
            $testComparison = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $TempAcl.ForcePrincipal

            $testComparison.ToBeRemoved.Rule.Count | Should be $TempAccessRules.Count
            $testComparison.Rules.Count | Should be $TempAcl.AccessControlEntry.Count
        }
    }

    Context "Compare-NtfsRule with Ensure set to Present with matching rules" {
        $pathName = "$TestDrive\TestDirectory"
        $TempAcl = New-AccessControlList -Principal "Everyone" -ForcePrincipal $false -AccessControlType Allow -FileSystemRights "Modify" -Inheritance "This Folder Only" -Ensure Present
        $ContextParams = @{
            Path = $pathName
            AccessControlList = $TempAcl
        }

        $TempAccessRules = @(
            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    'Modify',
                    'None',
                    'None',
                    'Allow'
                )

            New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $TempAcl.Principal,
                    @('CreateFiles', 'AppendData'),
                    @('ContainerInherit', 'ObjectInherit'),
                    'InheritOnly',
                    'Allow'
                )
        )

        Set-NewTempItemAcl -ItemType Directory -Path $ContextParams.Path -AccessRulesToAdd $TempAccessRules

        $Principal = $TempAcl.Principal
        $Identity = Resolve-Identity -Identity $Principal
        $IdentityRef = [System.Security.Principal.NTAccount]::new($Identity.Name)
        $ACLRules += ConvertTo-FileSystemAccessRule -AccessControlList $TempAcl -IdentityRef $IdentityRef

        $currentACL = Get-Acl -Path $pathName
        $actualAce = $currentAcl.Access.Where({$_.IdentityReference -eq $Identity.Name})

        It "Should have classify rules differently" {
            $testComparison = Compare-NtfsRule -Expected $ACLRules -Actual $actualAce -Force $TempAcl.ForcePrincipal

            $testComparison.ToBeRemoved.Rule.Count | Should be ($TempAccessRules.Count - $TempAcl.AccessControlEntry.Count)
            $testComparison.Rules.Count | Should be $TempAcl.AccessControlEntry.Count
            $testComparison.Rules.Match | Should be $true
        }
    }
}

Describe "$DSCResourceName\ResourceHelper\Resolve-Identity" {
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

Describe "$DSCResourceName\ResourceHelper\ConvertTo-SID" {
    Context "Identity will contain a '\' e.g. BUILTIN\Users" {
        It "Should return a proper SID" {
            $SID = ConvertTo-SID -IdentityReference "BUILTIN\Users"

            $SID.Value | Should be "S-1-5-32-545"
        }
    }
}

Describe "$DSCResourceName\ResourceHelper\Remove-NtPrincipalDomain" {
    Context 'Identity will have the domain removed' {
        $identity = [System.Security.Principal.NTAccount]::new('userDomain', 'userPrincipal')
        $result = Remove-NtPrincipalDomain -Identity $identity

        It 'Should be a System.Security.Principal.NTAccount Object' {
            $result | Should -BeOfType System.Security.Principal.NTAccount
        }

        It 'Should return a domain-less/workgroup-less userPrincipal' {
            $result.ToString() | Should -Be 'userPrincipal'
        }
    }
}

Describe "$DSCResourceName\NTFSAccessEntry\Update-NtfsAccessControlEntry" {
    Context 'Update a FileSystemAccessRule' {
        Mock -CommandName Remove-NtPrincipalDomain -MockWith {
            [System.Security.Principal.NTAccount]::new('userPrincipal')
        }
        $identity = [System.Security.Principal.NTAccount]::new('userDomain', 'userPrincipal')
        $ace = [System.Security.AccessControl.FileSystemAccessRule]::new($identity, 'FullControl', 'Allow')
        $modifiedId = [System.Security.Principal.NTAccount]::new('userPrincipal')
        $result = Update-NtfsAccessControlEntry -AccessControlEntry $ace

        It 'Should be a System.Security.AccessControl.FileSystemAccessRule Object' {
            $result | Should -BeOfType System.Security.AccessControl.FileSystemAccessRule
        }

        It 'Should update a FileSystemAccessRule with the correct ACE and UserPrincipal' {
            $result.IdentityReference | Should -Be $modifiedId
            $result.FileSystemRights  | Should -Be $ace.FileSystemRights
            $result.AccessControlType | Should -Be $ace.AccessControlType
        }
    }
}
