#requires -Version 4.0 -Modules Pester
#region HEADER

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

function Invoke-TestCleanup
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment
}

# Begin Testing
try
{
    InModuleScope $script:dscResourceName {
        Import-Module (Join-Path -Path ($PSScriptRoot | Split-Path) -ChildPath 'TestHelper.psm1') -Force

        $folderPath = 'c:\auditFolder'

        $nameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
        $cimFileSystemAuditRule = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRule += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
            AuditFlags = 'Success'
            FileSystemRights = @('ExecuteFile')
            Inheritance = 'This folder subfolders and files'
            Ensure = "Present"
        }
    
        $cimfileSystemAuditRuleList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRuleList += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
            Principal = 'BUILTIN\Users'
            ForcePrincipal = $true
            AuditRuleEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRule)
        }

        $cimFileSystemAuditRuleFalse += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
            AuditFlags = 'Fail'
            FileSystemRights = @('ExecuteFile')
            Inheritance = 'This folder subfolders and files'
            Ensure = ""
        }

        $cimFileSystemAuditRuleListFail += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
            Principal = 'BUILTIN\Users'
            ForcePrincipal = $False
            AuditRuleEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRuleFalse)
        }
        
        $cimFileSystemAuditRuleTestTrue = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRuleTestTrue += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
            AuditFlags = 'Success'
            FileSystemRights = @('Write')
            Inheritance = 'This folder subfolders and files'
            Ensure = "Present"
        }

        $cimfileSystemAuditRuleListTestTrue = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRuleListTestTrue += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
            Principal = 'BUILTIN\Users'
            ForcePrincipal = $true
            AuditRuleEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRuleTestTrue)
        }

        $cimFileSystemAuditRuleTestFalse = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimFileSystemAuditRuleTestFalse += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
            AuditFlags = 'Fail'
            FileSystemRights = @('Write')
            Inheritance = 'This folder subfolders and files'
            Ensure = "Present"
        }

        $cimfileSystemAuditRuleListTestFalse = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
        $cimfileSystemAuditRuleListTestFalse += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
            Principal = 'BUILTIN\Users'
            ForcePrincipal = $true
            AuditRuleEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRuleTestFalse)
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
            $setParameters = @{
                Path = $env:Temp
                AuditRuleList = @($cimfileSystemAuditRuleList)
                Force = $true
            }

            $auditRuleFail = ConvertTo-FileSystemAuditRule -AuditRuleList $cimFileSystemAuditRuleListFail[0] -IdentityRef (New-Object System.Security.Principal.NTAccount('BUILTIN\Users'))
            $auditRule = ConvertTo-FileSystemAuditRule -AuditRuleList $cimfileSystemAuditRuleList[0] -IdentityRef (New-Object System.Security.Principal.NTAccount('BUILTIN\Users'))
            $setAcl = Get-AuditAcl -Path $env:Temp
            $setAcl | Add-Member -MemberType NoteProperty -Value $auditRule.Rules -Name Audit -Force

            Mock -CommandName Write-CustomVerboseMessage
            Mock -CommandName Set-Acl
            Mock -CommandName Get-AuditAcl -MockWith { $setAcl }

            Context 'Force is TRUE' {
                It 'Should call Write-CustomVerboseMessage with ActionRemoveAudit' {
                    Set-TargetResource @setParameters
                    Assert-MockCalled -CommandName Write-CustomVerboseMessage -ParameterFilter {$Action -eq 'ActionRemoveAudit'}
                }
            }

            Context 'Force is FALSE' {
                $setParameters.Force = $false
                $setAcl | Add-Member -MemberType NoteProperty -Value $auditRuleFail.Rules -Name Audit -Force
                Mock -CommandName Get-AuditAcl -MockWith { $setAcl }
                It 'Should call Write-CustomVerboseMessage with ActionAddAudit' {
                    Set-TargetResource @setParameters
                    Assert-MockCalled -CommandName Write-CustomVerboseMessage -ParameterFilter {$Action -eq 'ActionAddAudit'}
                }
            }
        }

        Describe 'Test-TargetResource' -Tag 'Test' {
            $testParameters = @{
                Path = $env:Temp
                AuditRuleList = @($cimFileSystemAuditRuleListTestTrue)
                Force = $true
            }

            Mock -CommandName Write-CustomVerboseMessage
            Context 'When the system is in the desired state' {
                $auditRule = ConvertTo-FileSystemAuditRule -AuditRuleList $cimFileSystemAuditRuleListTestTrue[0] -IdentityRef (New-Object System.Security.Principal.NTAccount('BUILTIN\Users'))
                $setAcl = Get-AuditAcl -Path $env:Temp
                $setAcl | Add-Member -MemberType NoteProperty -Value $auditRule.Rules -Name Audit -Force
                Mock -CommandName Get-Acl -MockWith { $setAcl }
                It 'Should return TRUE' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should -Be $true
                }
            }

            Context 'When the system is not in the desired state' {
                $testParameters.Force = $false
                $auditRule = ConvertTo-FileSystemAuditRule -AuditRuleList $cimfileSystemAuditRuleListTestFalse[0] -IdentityRef (New-Object System.Security.Principal.NTAccount('BUILTIN\Users'))
                $setAcl = Get-AuditAcl -Path $env:Temp
                $setAcl | Add-Member -MemberType NoteProperty -Value $auditRule.Rules -Name Audit -Force
                Mock -CommandName Get-Acl -MockWith { $setAcl }
                It 'Should return FALSE' {
                    $testResult = Test-TargetResource @testParameters
                    $testResult | Should -Be $false
                }
            }
        }
    }
}
finally
{
    Invoke-TestCleanup
}
