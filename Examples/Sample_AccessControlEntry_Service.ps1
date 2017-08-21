# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestAceResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestFolder = "C:\powershell\deleteme\dsc_test"

    Node 'localhost' 
    {
        AccessControlEntry UsersRestartBitsService 
        {
            Ensure     = "Present"
            Path       = "bits"
            ObjectType = "Service"
            AceType    = "AccessAllowed"
            AccessMask = ([PowerShellAccessControl.ServiceAccessRights] "Start, Stop")
            Principal  = "Everyone"
        }
    }
}
