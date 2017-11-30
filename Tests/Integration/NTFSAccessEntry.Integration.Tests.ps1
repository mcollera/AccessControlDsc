#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

#region Set up for tests
$DSCModuleName   = 'AccessControlDSC'
$DSCResourceName = 'NTFSAccessEntry'

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
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($DSCResourceName).Config.ps1"
    . $ConfigFile

    #Create temporary directory
    $TestDirectory = New-Item -Path $TestParameter.Path -ItemType Directory -Force -Verbose
    $Acl = $TestDirectory.GetAccessControl()
    $Acl.SetAccessRuleProtection($false, $false)
    $Acl.Access.Where({-not $_.IsInherited}).ForEach({[Void]$Acl.RemoveAccessRule($_)})
    [System.IO.Directory]::SetAccessControl($TestDirectory.FullName, $Acl)

    Describe "$($DSCResourceName)_Integration" {

        $ConfigurationName = "$($DSCResourceName)_Test"

        It 'Should compile without throwing' {
            {
                & $ConfigurationName -OutputPath $TestParameter.Path
                Start-DscConfiguration -Path $TestParameter.Path -ComputerName localhost -Force -Verbose -Wait
            } | Should Not Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {

            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
        }

        # This test will pass locally but will fail in AppVeyor. Remove the Pending switch to run locally.
        It -Pending 'Should have set the resource and all the parameters should match' {
            
            Start-DscConfiguration -Path $TestParameter.Path -ComputerName localhost -Force -Verbose -Wait

            $CurrentConfiguration = Get-DscConfiguration | Where-Object -FilterScript {$_.ConfigurationName -eq $ConfigurationName}

            $CurrentConfiguration.AccessControlList.ForcePrincipal | Should Be $TestParameter.ForcePrincipal
            $CurrentConfiguration.Path | Should Be $TestParameter.Path
            $CurrentConfiguration.AccessControlList.Principal | Should Be $TestParameter.Principal
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
    if ($TestDirectory)
    {
        Remove-Item -Path $TestDirectory.FullName -Force -Recurse -Verbose
    }
}
