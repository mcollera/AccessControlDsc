﻿function Set-NewTempItemAcl
{
    <#
    .SYNOPSIS
        Creates a new temporary directory or file and sets its Access Control List (ACL).

    .PARAMETER ItemType
        Used in New item. Default is set to Directory

    .PARAMETER Path
        Path where the Item will be created

    .PARAMETER AccessRuleToAdd
        Access Rules you wish to add to a specific principal. Can be left blank and no rules will be created except a default full control for the current user

    .PARAMETER PassThru
        Switch to pass the entire object thru if you wish to use it

    .DESCRIPTION
        The Set-NewTempItemAcl function creates a new temporary directory or file and sets its Access Control List (ACL):
        - Disables NTFS permissions inheritance.
        - Removes all permission entries.
        - Grants Full Control permission to the calling user to ensure the file can be removed later.
        - Optionally adds additional permission entries.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateSet('Directory', 'File')]
        [String]
        $ItemType = 'Directory',

        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path = (Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ([System.IO.Path]::GetRandomFileName())),

        [Parameter(Mandatory = $false)]
        [System.Security.AccessControl.FileSystemAccessRule[]]
        $AccessRulesToAdd,

        [Parameter(Mandatory = $false)]
        [Switch]
        $PassThru
    )

    try
    {
        $TempItem = New-Item -Path $Path -ItemType $ItemType -Force -ErrorAction Stop -Verbose:$VerbosePreference
        $Acl = $TempItem.GetAccessControl()

        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access.ForEach({[Void]$Acl.RemoveAccessRule($_)})

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name

        if ($ItemType -eq 'Directory')
        {
            $DefaultAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $CurrentUser,
                    'FullControl',
                    @('ContainerInherit',
                    'ObjectInherit'),
                    'None',
                    'Allow'
                )

        }
        else
        {
            $DefaultAccessRule = New-Object -TypeName System.Security.AccessControl.FileSystemAccessRule `
                -ArgumentList @(
                    $CurrentUser,
                    'FullControl',
                    'None',
                    'None',
                    'Allow'
                )
        }

        $Acl.AddAccessRule($DefaultAccessRule)

        if ($PSBoundParameters.ContainsKey('AccessRulesToAdd'))
        {
            $AccessRulesToAdd.ForEach({$Acl.AddAccessRule($_)})
        }

        if ($ItemType -eq 'Directory')
        {
            [System.IO.Directory]::SetAccessControl($TempItem.FullName, $Acl)
        }
        else
        {
            [System.IO.File]::SetAccessControl($TempItem.FullName, $Acl)
        }

        if ($PassThru)
        {
            return $TempItem
        }
    }
    catch
    {
        throw
    }
}

function New-AccessControlList
{
<#
    .SYNOPSIS
    Creates an Access Control List Ciminstance
    
    .PARAMETER Principal
    Name of the principal which access rights are being managed 
    
    .PARAMETER ForcePrincipal
        Used to force the desired access rule
    
    .PARAMETER AccessControlType
    States if the principal should be will be allowed or denied access
    
    .PARAMETER FileSystemRights
    What rights the principal is being given over an object
    
    .PARAMETER Inheritance
    The inheritance properties of the object being managed
    
    .PARAMETER Ensure
    Either Present or Absent
#>
    param
    (
        [Parameter(Mandatory = $true)]
        $Principal,

        [Parameter(Mandatory = $true)]
        [boolean]
        $ForcePrincipal,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow","Deny")]
        [string]
        $AccessControlType,

        [Parameter(Mandatory = $false)]
        [ValidateSet("ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "Traverse", "ExecuteFile", "DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", "Write", "Delete", "ReadPermissions", "Read", "ReadAndExecute", "Modify", "ChangePermissions", "TakeOwnership", "Synchronize", "FullControl")]
        $FileSystemRights,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("This Folder Only","This Folder Subfolders and Files","This Folder and Subfolders","This Folder and Files","Subfolders and Files Only","Subfolders Only","Files Only")]
        [String]
        $Inheritance,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $CimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($null -eq $FileSystemRights)
    {
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
                                Principal = $Principal
                                ForcePrincipal = $ForcePrincipal
                            }
    }
    else
    {
        $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlEntry -Property @{
                                AccessControlType = $AccessControlType
                                FileSystemRights = @($FileSystemRights)
                                Inheritance = $Inheritance
                                Ensure = $Ensure
                            }
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
                            Principal = $Principal
                            ForcePrincipal = $ForcePrincipal
                            AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntry)
                        }
    }
    Return $CimAccessControlList
}

function New-RegistryAccessControlList
{
<#
    .SYNOPSIS
        Creates an Access Control List Ciminstance for registry rules
    
    .PARAMETER Principal
        Name of the principal which access rights are being managed 
    
    .PARAMETER ForcePrincipal
        Used to force the desired access rule
    
    .PARAMETER AccessControlType
        States if the principal should be will be allowed or denied access
    
    .PARAMETER RegistryRights
        Rights to be given to a principal over an object
    
    .PARAMETER Inheritance
        The inheritance properties of the object being managed
    
    .PARAMETER Ensure
        Either Present or Absent
#>
    param
    (
        [Parameter(Mandatory = $true)]
        $Principal,

        [Parameter(Mandatory = $true)]
        [boolean]
        $ForcePrincipal,

        [Parameter(Mandatory = $false)]
        [ValidateSet("Allow","Deny")]
        [string]
        $AccessControlType,

        [Parameter(Mandatory = $false)]
        [ValidateSet("ChangePermissions", "CreateLink", "CreateSubkey", "Delete", "EnumerateSubKeys", "ExecuteKey", "FullControl", "Notify", "QueryValues", "ReadKey", "ReadPermissions", "SetValue", "TakeOwnership", "WriteKey")]
        $RegistryRights,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("Key", "KeySubkeys", "Subkeys")]
        [String]
        $Inheritance,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $CimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($null -eq $RegistryRights)
    {
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
                            Principal = $Principal
                            ForcePrincipal = $ForcePrincipal
                        }
    }
    else
    {
        $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlEntry -Property @{
                            AccessControlType = $AccessControlType
                            Rights = @($RegistryRights)
                            Inheritance = $Inheritance
                            Ensure = $Ensure
                        }
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
                            Principal = $Principal
                            ForcePrincipal = $ForcePrincipal
                            AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntry)
                        }
    }
    Return $CimAccessControlList
}

function Set-NewTempRegKeyAcl
{
    <#
    .SYNOPSIS
        Creates a new temporary RegistryKey and sets its Access Control List (ACL).

    .PARAMETER Path
        Path where the Item will be created

    .PARAMETER AccessRuleToAdd
        Access Rules you wish to add to a specific principal. Can be left blank and no rules will be created except a default full control for the current user

    .PARAMETER PassThru
        Switch to pass the entire object thru if you wish to use it

    .DESCRIPTION
        The Set-NewTempRegKeyAcl function creates a new temporary Registry Key and sets its Access Control List (ACL):
        - Disables NTFS permissions inheritance.
        - Removes all permission entries.
        - Grants Full Control permission to the calling user to ensure the file can be removed later.
        - Optionally adds additional permission entries.
    #>
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Path,

        [Parameter(Mandatory = $false)]
        [System.Security.AccessControl.RegistryAccessRule[]]
        $AccessRulesToAdd,

        [Parameter(Mandatory = $false)]
        [Switch]
        $PassThru
    )

    try
    {
        $TempItem = New-Item -Path $Path -Force -ErrorAction Stop -Verbose:$VerbosePreference
        $Acl = $TempItem.GetAccessControl()

        $Acl.SetAccessRuleProtection($true, $false)
        $Acl.Access.ForEach({[Void]$Acl.RemoveAccessRule($_)})

        $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name


        $DefaultAccessRule = New-Object System.Security.AccessControl.RegistryAccessRule  `
            -ArgumentList @(
                $CurrentUser,
                'FullControl',
                @('ContainerInherit',
                'ObjectInherit'),
                'None',
                'Allow'
            )

        $Acl.AddAccessRule($DefaultAccessRule)

        if ($PSBoundParameters.ContainsKey('AccessRulesToAdd'))
        {
            $AccessRulesToAdd.ForEach({$Acl.AddAccessRule($_)})
        }

        $tempItem.SetAccessControl($Acl)

        if ($PassThru)
        {
            return $TempItem
        }
    }
    catch
    {
        throw
    }
}
