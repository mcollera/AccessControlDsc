#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

#region Set up for tests
$DSCModuleName   = 'AccessControlDSC'
$DSCResourceName = 'RegistryAccessEntry'

Import-Module "$($PSScriptRoot)\..\TestHelper.psm1" -Force
Import-Module Pester -Force

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

    #Create a temporary file to hold the configuration
    $configPath = "C:\TestRegConfig"
    New-Item -Path $configPath -ItemType Directory

    Describe "$($DSCResourceName)_Integration" {

        #Create temporary Registry Key
        $TestRegistryKey = Set-NewTempRegKeyAcl -Path $TestParameter.Path -PassThru
        $Acl = $TestRegistryKey.GetAccessControl()
        $Acl.SetAccessRuleProtection($false, $false)
        Set-Acl -Path $TestParameter.Path -AclObject $Acl

        $ConfigurationName = "$($DSCResourceName)_Test"
        It 'Should compile without throwing' {
            {
                & $ConfigurationName -OutputPath $ConfigPath
                Start-DscConfiguration -Path $configPath -ComputerName localhost -Force -Verbose -Wait
            } | Should Not Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {

            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
        }

        # This test will pass locally but will fail in AppVeyor. Remove the Pending switch to run locally. 
        It -Pending 'Should have set the resource and all the parameters should match' {
            
            Start-DscConfiguration -Path $configPath -ComputerName localhost -Force -Verbose -Wait

            $CurrentConfiguration = Get-DscConfiguration | Where-Object -FilterScript {$_.ConfigurationName -eq $ConfigurationName}

            Test-Path -Path $TestParameter.Path

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
    if (Test-Path $TestParameter.path)
    {
        Remove-Item -Path $TestParameter.path -Force -Recurse -Verbose
    }
    if (Test-Path $configPath)
    {
        Remove-Item -Path $configPath -Force -Recurse -Verbose
    }
}
