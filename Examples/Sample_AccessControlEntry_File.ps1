# Needed for ServiceAccessRights enumeration
Import-Module AccessControlDsc

Configuration TestAceResource 
{
    Import-DscResource -Module AccessControlDsc

    $TestFolder = "C:\powershell\deleteme\dsc_test"

    Node 'localhost' 
    {
        File TestFolder
        {
            Ensure          = "Present"
            Type            = "Directory"
            DestinationPath = $TestFolder
        }

        # Here's where resource provider to control modifying ACL protection would go
        AccessControlEntry EveryoneModifyTestFolder 
        {
            Ensure     = "Present"
            Path       = $TestFolder
            AceType    = "AccessAllowed"
            ObjectType = "Directory"
            AccessMask = ([System.Security.AccessControl.FileSystemRights]::Modify)
            Principal  = "Everyone"
            DependsOn  = "[File]TestFolder"
        }

        AccessControlEntry EveryoneAuditTestFolder 
        {
            Ensure       = "Present"
            Path         = $TestFolder
            AceType      = "SystemAudit"
            ObjectType   = "Directory"
            AccessMask   = ([System.Security.AccessControl.FileSystemRights]::FullControl)
            Principal    = "Everyone"
            AuditSuccess = $true
            AuditFailure = $true
            DependsOn    = "[File]TestFolder"
        }
    }
}
