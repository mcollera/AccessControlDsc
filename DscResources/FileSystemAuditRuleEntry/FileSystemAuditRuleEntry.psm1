$resourceRootPath = Split-Path -Path $PSScriptRoot -Parent
$resourceHelperPath = Join-Path -Path $resourceRootPath -ChildPath 'AccessControlResourceHelper'
$resourceHelperPsm1 = Join-Path -Path $resourceHelperPath -ChildPath 'AccessControlResourceHelper.psm1'
Import-Module -Name $resourceHelperPsm1 -Force

try
{
    $importLocalizedDataParams = @{
        BaseDirectory = $resourceHelperPath
        UICulture     = $PSUICulture
        FileName      = 'AccessControlResourceHelper.strings.psd1'
        ErrorAction   = 'Stop'
    }
    $script:localizedData = Import-LocalizedData @importLocalizedDataParams
}
catch
{
    $importLocalizedDataParams.UICulture = 'en-US'
    try
    {
        $script:localizedData = Import-LocalizedData @importLocalizedDataParams
    }
    catch
    {
        throw 'Unable to load localized data'
    }
}

function Get-TargetResource
{
    [CmdletBinding()]
    [OutputType([Hashtable])]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        $Path,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AuditRuleList
    )

    $nameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $cimfileSystemAuditRuleList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $inputPath = Get-InputPath($Path)

    if (Test-Path -Path $inputPath)
    {
        #$fileSystemItem = Get-Item -Path $inputPath -ErrorAction Stop
        #$currentAcl = $fileSystemItem.GetAccessControl('Audit')
        $currentAcl = Get-Acl -Path $inputPath -Audit        

        if ($null -ne $currentAcl)
        {
            $message = $localizedData.AclFound -f $inputPath
            Write-Verbose -Message $message

            foreach ($principal in $AuditRuleList)
            {
                $cimFileSystemAuditRule = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

                $principalName = $principal.Principal
                $forcePrincipal = $principal.ForcePrincipal

                $identity = Resolve-Identity -Identity $principalName
                $currentPrincipalAccess = $currentAcl.Audit.Where({$_.IdentityReference -eq $identity.Name})

                foreach ($access in $currentPrincipalAccess)
                {
                    $auditFlags = $access.AuditFlags.ToString()
                    $fileSystemRights = $access.FileSystemRights.ToString().Split(',').Trim()
                    $Inheritance = Get-NtfsInheritenceName -InheritanceFlag $access.InheritanceFlags.value__ -PropagationFlag $access.PropagationFlags.value__

                    $cimFileSystemAuditRule += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRule -Property @{
                        AuditFlags = $auditFlags
                        FileSystemRights = @($fileSystemRights)
                        Inheritance = $Inheritance
                        Ensure = ""
                    }
                }

                $cimFileSystemAuditRuleList += New-CimInstance -ClientOnly -Namespace $nameSpace -ClassName FileSystemAuditRuleList -Property @{
                    Principal = $principalName
                    ForcePrincipal = $forcePrincipal
                    FileSystemAuditRule = [Microsoft.Management.Infrastructure.CimInstance[]]@($cimFileSystemAuditRule)
                }
            }

        }
        else
        {
            $message = $localizedData.AclNotFound -f $inputPath
            Write-Verbose -Message $message
        }
    }
    else
    {
        $Message = $localizedData.ErrorPathNotFound -f $inputPath
        Write-Verbose -Message $Message
    }

    $returnValue = @{
        Force = $Force
        Path = $inputPath
        FileSystemAuditRuleList = $cimfileSystemAuditRuleList
    }

    return $returnValue
}

function Set-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AuditRuleList,

        [Parameter()]
        [bool]
        $Force = $false
    )
}

function Test-TargetResource
{
    [CmdletBinding()]
    [OutputType([System.Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path,

        [Parameter(Mandatory=$true)]
        [Microsoft.Management.Infrastructure.CimInstance[]]
        $AuditRuleList,

        [Parameter()]
        [bool]
        $Force = $false
    )
}

function Get-InputPath
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.String]
        $Path
    )

    $returnPath = $Path

    # If Path has a environment variable, convert it to a locally usable path
    $returnPath = [System.Environment]::ExpandEnvironmentVariables($Path)

    return $returnPath
}
