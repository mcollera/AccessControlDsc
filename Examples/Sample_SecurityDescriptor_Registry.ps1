# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestSecurityDescriptorResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestKey = "HKLM:\SOFTWARE\Dsc_Test_sd"

    Node 'localhost' 
    {
        Registry TestKey
        {
            Ensure    = "Present"
            Key       = $TestKey
            ValueName = "" 
        }

        SecurityDescriptor TestKeyFullSd 
        { 
            Path       = $TestKey
            ObjectType = "RegistryKey"
            Owner      = "Administrators"
            Group = "Administrators"
            Access     = @"
                Principal,RegistryRights
                Administrators,FullControl
                Users,ReadKey
"@
            Audit      = @"
                AceType,Principal,RegistryRights,AuditFailure
                SystemAudit,Everyone,FullControl,true
"@
            DependsOn  = "[Registry]TestKey"
        }
    }
}
