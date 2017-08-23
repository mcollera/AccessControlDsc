param(
    [parameter()]
    [string]
    $TargetName = '192.168.1.41',

    [parameter()]
    [string]
    $OutputPath = 'C:\temp\mof'
)

[DSCLocalConfigurationManager()]
Configuration LCMConfig
{
    Node $TargetName
    {
        Settings   
        {                              
            RebootNodeIfNeeded = $TRUE
            ConfigurationModeFrequencyMins = 15
            ConfigurationMode = 'ApplyAndAutoCorrect'
        } 
    }
}


configuration Sample_NTFSAccessControl
{
    Import-DscResource -ModuleName AccessControlDsc
    node $TargetName
    {
        NTFSAccessEntry Test
        {
            Path = "c:\test\sample.txt"
            AccessControlList = @(
                NTFSAccessControlList
                {
                    Principal = "Everyone"
                    ForcePrincipal = $true
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'Modify'
                            InheritanceFlags = 'ContainerInherit'
                        }
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            InheritanceFlags = 'None'
                        }
                    )               
                }
                NTFSAccessControlList
                {
                    Principal = "Users"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            InheritanceFlags =  'None'
                        }
                    )               
                }
            )
        }
    }
}

$credential = $(New-Object System.Management.Automation.PSCredential("administrator", $(ConvertTo-SecureString '!A@S3d4f5g6h7j8k' -AsPlainText -Force)))

$session = New-PSSession -ComputerName $TargetName -Credential $credential
$null = Copy-Item -Path "C:\Users\Administrator\Documents\WindowsPowerShell\Modules\AccessControlDsc" -Destination "C:\Program Files\WindowsPowerShell\Modules" -ToSession $session -Recurse -Force -ErrorAction Stop
$null = Remove-PSSession -Session $session

LCMConfig -OutputPath $OutputPath
Sample_NTFSAccessControl -OutputPath $OutputPath
Set-DscLocalConfigurationManager -Path $OutputPath -ComputerName $TargetName -Credential $credential -Force
Start-DscConfiguration -Path $OutputPath -ComputerName $TargetName -Credential $credential -Wait -Force