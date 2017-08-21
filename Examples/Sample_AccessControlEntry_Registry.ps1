# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestAceResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestKey = "HKLM:\SOFTWARE\Dsc_Test"

    Node 'localhost' 
    {
        Registry TestKey
        {
            Ensure    = "Present"
            Key       = $TestKey
            ValueName = "" 
        }

        AccessControlEntry EveryoneFullControlTestKey 
        {
            Ensure     = "Present"
            Path       = $TestKey
            ObjectType = "RegistryKey"
            AceType    = "AccessAllowed"
            AccessMask = ([System.Security.AccessControl.RegistryRights]::ReadPermissions)
            Principal  = "Everyone"
            DependsOn  = "[Registry]TestKey"
        }
    }
}
