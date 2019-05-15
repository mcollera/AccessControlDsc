configuration Sample_FileAuditEntry
{
    Import-DscResource -ModuleName AccessControlDsc

    node localhost
    {
        FileSystemAuditRuleEntry auditFolder
        {
            Path = "C:\auditFolder\auditChildFolder"
            Force = $true
            AuditRuleList = @(
                FileSystemAuditRuleList
                {
                    Principal = 'users'
                    ForcePrincipal = $false
                    AuditRuleEntry = @(
                        FileSystemAuditRule
                        {
                            AuditFlags = 'Success'
                            FileSystemRights = 'Write'
                            Inheritance = 'This folder and files'
                            Ensure = 'Present'
                        }
                    )
                }
            )
        }
    }
}
