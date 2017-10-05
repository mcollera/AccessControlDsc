
$TestParameter = [PSCustomObject]@{
    Ensure = 'Present'
    Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([Guid]::NewGuid().Guid))
    Principal = 'BUILTIN\Users'
    ForcePrincipal = $true
}

Configuration NTFSAccessEntry_Test
{
    Import-Module "$($PSScriptRoot)\..\..\DSCResources\$($Global:DSCResourceName)\$($Global:DSCResourceName).psm1" -Force

    Node localhost
    {
        NTFSAccessEntry Test
        {
            Path = $TestParameter.Path
            AccessControlList = @(
                NTFSAccessControlList
                {
                    Principal = $TestParameter.Principal
                    ForcePrincipal = $TestParameter.ForcePrincipal
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'Modify'
                            Inheritance = 'This folder and files'
                            Ensure = $TestParameter.Ensure
                        }
                    )               
                }
            )
        }
    }
}
