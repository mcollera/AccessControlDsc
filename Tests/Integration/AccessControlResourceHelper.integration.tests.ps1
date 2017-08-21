#requires -RunAsAdministrator

# Get the root path of the resourse
[String] $script:moduleRoot = Split-Path -Parent ( Split-Path -Parent $PSScriptRoot )

Import-Module -Name (Join-Path -Path $moduleRoot `
                               -ChildPath 'DSCResources\AccessControlResourceHelper\AccessControlResourceHelper.psm1' ) `
                               -Force
#region Generate data
