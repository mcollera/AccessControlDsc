$TestParameter = [PSCustomObject]@{
    Ensure = 'Present'
    Path = 'HKLM:\Software\TestKey'
    Principal = 'Everyone'
    ForcePrincipal = $true
}

Configuration RegistryAccessEntry_Test
{
    Import-DscResource  -Name "RegistryAccessEntry"

    Node localhost
    {
        RegistryAccessEntry Test
        {
            Path = $TestParameter.Path
            AccessControlList = @(
                AccessControlList
                {
                    Principal = $TestParameter.Principal
                    ForcePrincipal = $TestParameter.ForcePrincipal
                    AccessControlEntry = @(
                        AccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            Rights = 'CreateSubkey'
                            Inheritance = 'This Key and Subkeys'
                            Ensure = $TestParameter.Ensure
                        }
                    )               
                }
            )
        }
    }
}
