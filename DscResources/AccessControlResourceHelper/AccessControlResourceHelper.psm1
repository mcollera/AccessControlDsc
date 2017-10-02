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
        try
        {
            Write-Verbose -Message "Resolving identity for '$Identity'."

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
            $ErrorMessage = "Could not resolve identity '{0}': '{1}'." -f $Identity, $_.Exception.Message
            Write-Error -Exception $_.Exception -Message $ErrorMessage
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

    If($IdentityReference.Contains("\"))
    {
        $IdentityReference = $IdentityReference.split('\')[1]
    }
    
    [System.Security.Principal.NTAccount]$PrinicipalName = $IdentityReference
    $SID = $PrinicipalName.Translate([System.Security.Principal.SecurityIdentifier])

    Return $SID
}
