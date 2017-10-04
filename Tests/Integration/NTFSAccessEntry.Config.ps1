
$TestParameter = [PSCustomObject]@{
    Ensure = 'Present'
    Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([Guid]::NewGuid().Guid))
    Principal = 'BUILTIN\Users'
    ForcePrincipal = $true
}

Configuration NTFSAccessEntry_Test
{
    Import-DscResource -ModuleName AccessControlDsc

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