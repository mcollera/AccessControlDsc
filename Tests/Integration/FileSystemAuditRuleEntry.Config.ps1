$testParameter = [PSCustomObject]@{
    Ensure = 'Present'
    Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([Guid]::NewGuid().Guid))
    Principal = 'Users'
    ForcePrincipal = $true
}

Configuration FileSystemAuditRuleEntry_Test
{
    Import-DscResource -ModuleName AccessControlDsc

    Node localhost
    {
        FileSystemAuditRuleEntry auditFolder
        {
            Path = $testParameter.Path
            AuditRuleList = @(
                FileSystemAuditRuleList
                {
                    Principal = $testParameter.Principal
                    ForcePrincipal = $testParameter.ForcePrincipal
                    AuditRuleEntry = @(
                        FileSystemAuditRule
                        {
                            AuditFlags = 'Success'
                            FileSystemRights = 'Write'
                            Inheritance = 'This folder and files'
                            Ensure = $testParameter.Ensure
                        }
                    )
                }
            )
        }
    }
}
