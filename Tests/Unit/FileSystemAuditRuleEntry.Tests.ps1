<#
    .SYNOPSIS
        Template for creating DSC Resource Unit Tests

    .DESCRIPTION
        To Use:
        1. Copy to \Tests\Unit\ folder and rename <ResourceName>.tests.ps1
           (e.g. MSFT_xFirewall.tests.ps1).
        2. Customize TODO sections.
        3. Delete all template comments (TODOs, etc.).
        4. Remove any unused It-, Context-, BeforeAll-, AfterAll-,
           BeforeEach- and AfterEach-blocks.
        5. Remove this comment-based help.

    .NOTES
        There are multiple methods for writing unit tests. This template provides a few examples
        which you are welcome to follow but depending on your resource, you may want to
        design it differently. Read through our TestsGuidelines.md file for an intro on how to
        write unit tests for DSC resources: https://github.com/PowerShell/DscResources/blob/master/TestsGuidelines.md
#>

#requires -Version 4.0 -Modules Pester
#region HEADER
# TODO: Update to correct module name and resource name.
$script:dscModuleName = 'AccessControlDsc'
$script:dscResourceName = 'FileSystemAuditRuleEntry'

# Unit Test Template Version: 1.2.4
$script:moduleRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
if ( (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests'))) -or `
     (-not (Test-Path -Path (Join-Path -Path $script:moduleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1'))) )
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $script:moduleRoot -ChildPath 'DscResource.Tests'))
}

Import-Module -Name (Join-Path -Path $script:moduleRoot -ChildPath (Join-Path -Path 'DSCResource.Tests' -ChildPath 'TestHelper.psm1')) -Force

# TODO: Insert the correct <ModuleName> and <ResourceName> for your resource
$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $script:dscModuleName `
    -DSCResourceName $script:dscResourceName `
    -ResourceType 'Mof' `
    -TestType Unit

#endregion HEADER

function Invoke-TestSetup
{
     # TODO: Optional init code goes here...
}

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    # TODO: Other Optional Cleanup Code Goes Here...
}

# Begin Testing
try
{
    Invoke-TestSetup

    InModuleScope $script:dscResourceName {
        Import-Module (Join-Path -Path ($PSScriptRoot | Split-Path) -ChildPath 'TestHelper.psm1') -Force

        # TODO: Optionally create any variables here for use by your tests
        $folderPath = 'c:\auditFolder'

        $nameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
        $cimFileSystemAuditRule = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRule += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
            AuditFlags = 'Success'
            FileSystemRights = @('ExecuteFile')
            Inheritance = 'This folder only'
            Ensure = ""
        }
    
        $cimfileSystemAuditRuleList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRuleList += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
            Principal = 'users'
            ForcePrincipal = $false
            AuditRuleEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRule)
        }
        
        $mockAcl = @{}
        $mockAcl.Audit = @(
            @{
                FileSystemRights  = 'Write'
                AuditFlags        = 'Success'
                IdentityReference = 'BUILTIN\Users'
                IsInherited       = $False
                InheritanceFlags  = @{Value__ = 1}
                PropagationFlags  = @{Value__ = 1}
            }
        )
        Mock -CommandName Test-Path -MockWith { return $true }
        Mock -CommandName Get-InputPath -MockWith { return $folderPath }
        Mock -CommandName Get-Acl -MockWith { $mockAcl }
        Mock -CommandName Get-NtfsInheritenceName -MockWith { return 'ObjectInherit' }

        Describe 'Get-TargetResource' -Tag 'Get' {
            $getParameters = @{
                Path = 'c:\auditFolder'
                AuditRuleList = @($cimfileSystemAuditRuleList)
            }

            Mock -CommandName Write-Verbose

            Context 'Standard tests' {
                It 'Should not throw' {
                    {Get-TargetResource @getParameters}| Should -Not -Throw
                }

                It 'Should return a hashtable' {
                    $getTargetResult = Get-TargetResource @getParameters
                    $getTargetResult -is [hashtable] | Should -Be $true
                }
            }

            Context 'Acl not found' {
                Mock -CommandName Get-Acl
                It 'Should call Write-Verbose with AclNotFound' {
                    $getTargetResult = Get-TargetResource @getParameters
                    $getTargetResult.AuditRuleList.Length -ge 1 | Should -Be $false
                    Assert-MockCalled -CommandName Write-Verbose -ParameterFilter {$Message -eq "Error obtaining 'c:\auditFolder' ACL."}

                }
            }

            Context 'Path not found' {
                Mock -CommandName Test-Path -MockWith { return $false }
                
                It 'Should call Write-Verbose with PathErrorPathNotFound' {
                    Get-TargetResource @getParameters
                    Assert-MockCalled -CommandName Write-Verbose -ParameterFilter {$Message -eq "The requested path 'c:\auditFolder' cannot be found."}
                }
            }
        }

        Describe 'Set-TargetResource' -Tag 'Set' {
            Context 'When the system is in the desired state' {
                It 'Should ...test-description' {
                    # test-code
                }
            }

            Context 'When the system is not in the desired state' {
                It 'Should ....test-description' {
                    # test-code
                }
            }
        }

        Describe 'MSFT_<ResourceName>\Test-TargetResource' -Tag 'Test' {
            Context 'When the system is in the desired state' {
                It 'Should ...test-description' {
                    # test-code
                }
            }

            Context 'When the system is not in the desired state' {
                It 'Should ....test-description' {
                    # test-code
                }
            }
        }

        Describe 'MSFT_<ResourceName>\Get-HelperFunction' -Tag 'Helper' {
            It 'Should ...test-description' {
                # test-code
            }

            It 'Should ....test-description' {
                # test-code
            }
        }

        # TODO: add more Describe blocks as needed
    }
}
finally
{
    Invoke-TestCleanup
}