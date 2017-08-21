# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestSecurityDescriptorResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestFolderOwner = "C:\powershell\deleteme\dsc_test_sd_owner"
    $TestFolderSacl = "C:\powershell\deleteme\dsc_test_sd_sacl"
    $TestFolderDacl = "C:\powershell\deleteme\dsc_test_sd_dacl"

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

        SecurityDescriptor TestFolderSdOwner 
        {  # This sets the owner to Administrators
            Path       = $TestFolderOwner
            ObjectType = "Directory"
            Owner      = "Administrators"
            DependsOn  = "[File]TestFolderOwner"
        }

        SecurityDescriptor TestFolderSdSacl 
        { 
            Path             = $TestFolderSacl
            ObjectType       = "Directory"
            AuditInheritance = "Enabled"
            Audit            = @"
                AceType,Principal,FolderRights,AuditSuccess,AuditFailure
                SystemAudit,Everyone,FullControl,false,true
                SystemAudit,Users,Delete,true,true
"@
            DependsOn        = "[File]TestFolderSacl"
        }

        SecurityDescriptor TestFolderSdDacl 
        {
            Path              = $TestFolderDacl
            ObjectType        = "Directory"
            AccessInheritance = "Disabled"
            Access            = @"
                AceType,Principal,FolderRights,AppliesTo,OnlyApplyToThisContainer
                AccessAllowed,Administrators,FullControl
                AccessAllowed,Users,Modify
                AccessDenied,Users,Delete,Object
                AccessDenied,Everyone,CreateDirectories,ChildContainers,true
"@
            DependsOn         = "[File]TestFolderDacl"
        }
    }
}
