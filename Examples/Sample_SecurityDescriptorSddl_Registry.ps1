# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestSecurityDescriptorSddlResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestKey = "HKLM:\SOFTWARE\Dsc_Test_sddl"

    Node 'localhost' 
    {
        Registry TestKey
        {
            Ensure    = "Present"
            Key       = $TestKey
            ValueName = "" 
        }

        SecurityDescriptorSddl TestKeyFullSd 
        {  # Instead of splitting the SD parts, use an SD with all parts
            Path       = $TestKey
            ObjectType = "RegistryKey"
            Sddl       = "O:BAG:SYD:PAI(A;OICI;KR;;;RC)(A;OICI;KA;;;SY)(A;OICI;KA;;;BA)(A;CI;KA;;;BU)"
            DependsOn  = "[Registry]TestKey"
        }
    }
}
