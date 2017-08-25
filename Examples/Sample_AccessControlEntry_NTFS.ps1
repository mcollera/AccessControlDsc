param(
    [parameter()]
    [string]
    $TargetName = '192.168.1.41',

    [parameter()]
    [string]
    $OutputPath = 'C:\temp\mof',

    [parameter(mandatory = $true)]
    [pscredential]
    [System.Management.Automation.CredentialAttribute()]
    $Credential
)

configuration Sample_NTFSAccessControl
{
    Import-DscResource -ModuleName AccessControlDsc
    node $TargetName
    {
        NTFSAccessEntry Test
        {
            Path = "c:\test"
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
                            Inheritance = 'This folder and files'
                            Ensure = 'Present'
                        }
                        NTFSAccessControlEntry
                        {
                            AccessControlType = 'Allow'
                            FileSystemRights = 'FullControl'
                            Inheritance = 'This folder and files'
                            Ensure = 'Present'
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
                            Inheritance = 'This folder and files'
                            Ensure = 'Present'
                        }
                    )               
                }
            )
        }
    }
}

$session = New-PSSession -ComputerName $TargetName -Credential $credential
$null = Copy-Item -Path "C:\Users\Administrator\Documents\WindowsPowerShell\Modules\AccessControlDsc" -Destination "C:\Program Files\WindowsPowerShell\Modules" -ToSession $session -Recurse -Force -ErrorAction Stop
$null = Remove-PSSession -Session $session

Sample_NTFSAccessControl -OutputPath $OutputPath
Start-DscConfiguration -Path $OutputPath -ComputerName $TargetName -Credential $credential -Wait -Force
