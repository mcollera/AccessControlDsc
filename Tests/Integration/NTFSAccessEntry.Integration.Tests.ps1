#requires -Version 4.0 -Modules Pester
#requires -RunAsAdministrator

$Global:DSCModuleName   = 'AccessControlDSC'
$Global:DSCResourceName = 'NTFSAccessEntry'

try
{
    $ConfigFile = Join-Path -Path $PSScriptRoot -ChildPath "$($Global:DSCResourceName).Config.ps1"
    . $ConfigFile

    #Create temporary directory
    $TestDirectory = New-Item -Path $TestParameter.Path -ItemType Directory -Force -Verbose
    $Acl = $TestDirectory.GetAccessControl()
    $Acl.SetAccessRuleProtection($false, $false)
    $Acl.Access.Where({-not $_.IsInherited}).ForEach({[Void]$Acl.RemoveAccessRule($_)})
    [System.IO.Directory]::SetAccessControl($TestDirectory.FullName, $Acl)

    #Integration Tests
    Describe "$($Global:DSCResourceName)_Integration" {

        $ConfigurationName = "$($Global:DSCResourceName)_Test"

        It 'Should compile without throwing' {
            {
                Invoke-Expression -Command ('{0} -OutputPath "{1}"' -f $ConfigurationName, $TestParameter.Path)
                Start-DscConfiguration -Path $TestParameter.Path -ComputerName localhost -Force -Verbose -Wait
            } | Should Not Throw
        }

        It 'Should be able to call Get-DscConfiguration without throwing' {

            { Get-DscConfiguration -Verbose -ErrorAction Stop } | Should Not Throw
        }

        It 'Should have set the resource and all the parameters should match' {
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
    # Remove temporary directory
    if ($TestDirectory)
    {
        Remove-Item -Path $TestDirectory.FullName -Force -Recurse -Verbose
    }
}
