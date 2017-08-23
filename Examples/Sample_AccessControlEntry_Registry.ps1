param(
    [parameter()]
    [string]
    $TargetName = '192.0.0.66',

    [parameter()]
    [string]
    $OutputPath = 'C:\temp\mof'
)

[DSCLocalConfigurationManager()]
Configuration RpsConfiguration
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


configuration Sample_AccessControl
{
    Import-DscResource -ModuleName AccessControlDsc
    node $TargetName
    {

        RegistryAccessEntry Test
        {
            Path = "HKLM:\Software\Test"
            AccessControlList = @(
                AccessControlList
                {
                    Principal = "Everyone"
                    ForcePrincipal = $true
                    AccessControlEntry = @(
                        AccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            Rights = 'CreateSubKey','ChangePermissions','Delete'
                            Inheritance = 'This Key Only'
                        }
                        AccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            Rights = 'FullControl'
                            Inheritance = 'SubKeys Only'
                        }
                    )               
                }
                AccessControlList
                {
                    Principal = "Users"
                    ForcePrincipal = $false
                    AccessControlEntry = @(
                        AccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            Rights = 'CreateSubKey','ChangePermissions','Delete'
                            Inheritance = 'This Key Only'
                        }
                    )               
                }
            )
        }
    }
}

$credential = $(New-Object System.Management.Automation.PSCredential("powerstig\administrator", $(ConvertTo-SecureString '!A@S3d4f5g6h7j8k9l' -AsPlainText -Force)))

$session = New-PSSession -ComputerName $TargetName -Credential $credential
$null = Copy-Item -Path 'C:\Program Files\WindowsPowerShell\Modules\AccessControlDsc' -Destination "C:\Program Files\WindowsPowerShell\Modules" -ToSession $session -Recurse -Force -ErrorAction Stop
$null = Remove-PSSession -Session $session

RpsConfiguration -OutputPath $OutputPath
Sample_AccessControl -OutputPath $OutputPath
Set-DscLocalConfigurationManager -Path $OutputPath -ComputerName $TargetName -Credential $credential -Force
Start-DscConfiguration -Path $OutputPath -ComputerName $TargetName -Credential $credential -Wait -Force