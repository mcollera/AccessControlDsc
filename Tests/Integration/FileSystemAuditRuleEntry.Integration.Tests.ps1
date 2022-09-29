#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

#region Set up for tests
$DSCModuleName   = 'AccessControlDSC'
$DSCResourceName = 'FileSystemAuditRuleEntry'

$ModuleRoot = Split-Path -Path $Script:MyInvocation.MyCommand.Path -Parent | Split-Path -Parent | Split-Path -Parent

if (
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests') -PathType Container)) -or
    (-not (Test-Path -Path (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -PathType Leaf))
)
{
    & git @('clone', 'https://github.com/PowerShell/DscResource.Tests.git', (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests'))
}

Import-Module -Name (Join-Path -Path $ModuleRoot -ChildPath 'DSCResource.Tests\TestHelper.psm1') -Force

$TestEnvironment = Initialize-TestEnvironment `
    -DSCModuleName $DSCModuleName `
    -DSCResourceName $DSCResourceName `
    -TestType Integration

#endregion

try
{
    $configFile = Join-Path -Path $PSScriptRoot -ChildPath "$($DSCResourceName).Config.ps1"
    . $configFile

    #Create temporary directory
    $testDirectory = New-Item -Path $TestParameter.Path -ItemType Directory -Force -Verbose
    $acl = $testDirectory.GetAccessControl()
    $acl.SetAccessRuleProtection($false, $false)
    $acl.Access.Where({-not $_.IsInherited}).ForEach({[Void]$Acl.RemoveAccessRule($_)})
    [System.IO.Directory]::SetAccessControl($testDirectory.FullName, $acl)

    Describe "$($DSCResourceName)_Integration" {

        $ConfigurationName = "$($DSCResourceName)_Test"

        It 'Should compile without throwing' {
            {
                & $ConfigurationName -OutputPath $testParameter.Path
                Start-DscConfiguration -Path $testParameter.Path -ComputerName localhost -Force -Verbose -Wait
            } | Should Not Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {

            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
        }

        # This test will pass locally but will fail in AppVeyor. Remove the Pending switch to run locally.
        It -Pending 'Should have set the resource and all the parameters should match' {
            
            Start-DscConfiguration -Path $TestParameter.Path -ComputerName localhost -Force -Verbose -Wait

            $currentConfiguration = Get-DscConfiguration | Where-Object -FilterScript {$_.ConfigurationName -eq $ConfigurationName}

            $currentConfiguration.AuditRuleList.ForcePrincipal | Should Be $testParameter.ForcePrincipal
            $currentConfiguration.Path | Should Be $testParameter.Path
            $currentConfiguration.AuditRuleList.Principal | Should Be $testParameter.Principal
        }

        It 'Actual configuration should match the desired configuration' {
            Test-DscConfiguration -Verbose | Should Be $true
        }
    }
}
finally
{
    Restore-TestEnvironment -TestEnvironment $TestEnvironment

    #Remove temporary directory
    if ($testDirectory)
    {
        Remove-Item -Path $testDirectory.FullName -Force -Recurse -Verbose
    }
}
