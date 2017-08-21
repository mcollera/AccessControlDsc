# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestSecurityDescriptorSddlResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestFolderOwner = "C:\powershell\deleteme\dsc_test_sddl_owner"
    $TestFolderSacl = "C:\powershell\deleteme\dsc_test_sddl_sacl"
    $TestFolderDacl = "C:\powershell\deleteme\dsc_test_sddl_dacl"

    Node 'localhost' 
    {
        File TestFolderOwner
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $TestFolderOwner
        }

        File TestFolderSacl
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $TestFolderSacl
        }

        File TestFolderDacl
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $TestFolderDacl
        }

        SecurityDescriptorSddl TestFolderSdOwner 
        {  # This sets the owner to Administrators
            Path       = $TestFolderOwner
            ObjectType = "Directory"
            Sddl       = "O:BA"
            DependsOn  = "[File]TestFolderOwner"
        }

        SecurityDescriptorSddl TestFolderSdSacl 
        { # Some auditing (2 not inherited; 1 inherited; only 2 non inherited should count)
            Path       = $TestFolderSacl
            ObjectType = "Directory"
            Sddl       = "S:AI(AU;OICISAFA;FA;;;WD)(AU;OICISA;WD;;;SY)(AU;OICIIDSA;FA;;;WD)"
            DependsOn  = "[File]TestFolderSacl"
        }

        SecurityDescriptorSddl TestFolderSdDacl 
        { # Protected DACL from Windows folder (so this should disable inheritance)
            Path       = $TestFolderDacl
            ObjectType = "Directory"
            Sddl       = "D:PAI(A;OICIIO;GA;;;CO)(A;OICIIO;GA;;;SY)(A;;0x1301bf;;;SY)(A;OICIIO;GA;;;BA)(A;;0x1301bf;;;BA)(A;OICIIO;GXGR;;;BU)(A;;0x1200a9;;;BU)(A;CIIO;GA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)"
            DependsOn  = "[File]TestFolderDacl"
        }
    }
}
