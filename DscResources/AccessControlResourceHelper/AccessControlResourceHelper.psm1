function Resolve-Identity
{
    <#
        .SYNOPSIS
            Resolves the principal name SID 

        .PARAMETER Identity
            Specifies the identity of the principal.

        .EXAMPLE
        Resolve-Identity -Identity "everyone"
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Identity
    )
    process
    {
        Write-Verbose -Message "Resolving identity for '$Identity'."

        $tryNTService = $false

        try 
        {
            if ($Identity -match '^S-\d-(\d+-){1,14}\d+$')
            {
                [System.Security.Principal.SecurityIdentifier]$Identity = $Identity
            }
            else
            {
                 [System.Security.Principal.NTAccount]$Identity = $Identity
            }

            $SID = $Identity.Translate([System.Security.Principal.SecurityIdentifier])
            $NTAccount = $SID.Translate([System.Security.Principal.NTAccount])

            $Principal = [PSCustomObject]@{
                Name = $NTAccount.Value
                SID = $SID.Value
            }

            return $Principal
        }
        catch
        {
            # Try to resolve identity to NT Service
            $tryNTService = $true
        }

        if ($tryNTService)
        {
            try
            {
                [System.Security.Principal.NTAccount]$Id = "NT Service\" + $Identity
                $SID = $Id.Translate([System.Security.Principal.SecurityIdentifier])
                $NTAccount = $SID.Translate([System.Security.Principal.NTAccount])
                
                $Principal = [PSCustomObject]@{
                    Name = $NTAccount.Value
                    SID = $SID.Value
                }
    
                return $Principal
            }
            catch
            {
                $ErrorMessage = "Could not resolve identity '{0}': '{1}'." -f $Identity, $_.Exception.Message
                Write-Error -Exception $_.Exception -Message $ErrorMessage
            }
        }        
    }
}

<#
    .SYNOPSIS
    Takes identity name and translates to SID

    .PARAMETER IdentityReference
    System.Security.Principal.NTAccount object 

    .EXAMPLE
    $IdentityReference = (Get-Acl -Path C:\temp).access[0].IdentityReference
    ConvertTo-SID -IdentityReference $IdentityReference
#>

function ConvertTo-SID
{
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $IdentityReference
    )

    try 
    {
        If($IdentityReference.Contains("\"))
        {
            $IdentityReference = $IdentityReference.split('\')[1]
        }
        
        [System.Security.Principal.NTAccount]$PrinicipalName = $IdentityReference
        $SID = $PrinicipalName.Translate([System.Security.Principal.SecurityIdentifier])
    
        Return $SID
    }
    catch 
    {
        # Probably NT Service which needs domain portion to translate without error
        [System.Security.Principal.NTAccount]$Id = "NT Service\" + $IdentityReference
        $SID = $Id.Translate([System.Security.Principal.SecurityIdentifier])

        return $SID
    }
    
}

function Assert-Module
{
    [CmdletBinding()]
    param
    (
        [Parameter()] [ValidateNotNullOrEmpty()]
        [System.String]
        $ModuleName
    )

    if (-not (Get-Module -Name $ModuleName -ListAvailable))
    {
        $errorId = '{0}_ModuleNotFound' -f $ModuleName;
        $errorMessage = $localizedString.RoleNotFoundError -f $ModuleName;
        ThrowInvalidOperationError -ErrorId $errorId -ErrorMessage $errorMessage;
    }
} 

Function Get-SchemaIdGuid
{
    Param 
    (
        [Parameter()]
        [string]
        $ObjectName
    )

    if($ObjectName)
    {
        $value = Get-ADObject -filter {name -eq $ObjectName} -SearchBase (Get-ADRootDSE).schemaNamingContext -prop schemaIDGUID
        return [system.guid]$value.schemaIDGUID 
    }
    else
    {
        return [system.guid]"00000000-0000-0000-0000-000000000000"
    }
}

Function Get-SchemaObjectName
{
    Param 
    (
        [Parameter()]
        [guid]
        $SchemaIdGuid
    )

    If($SchemaIdGuid)
    {
        $value = Get-ADObject -filter {schemaIDGUID  -eq $SchemaIdGuid} -SearchBase (Get-ADRootDSE).schemaNamingContext -prop schemaIDGUID
        return $value.name
    }
    else
    {
        return "none"
    } 
}
