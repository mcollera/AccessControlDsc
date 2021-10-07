function Set-NewTempItemAcl
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
        [ValidateSet("Allow", "Deny")]
        [string]
        $AccessControlType,

        [Parameter(Mandatory = $false)]
        [ValidateSet("ListDirectory", "ReadData", "WriteData", "CreateFiles", "CreateDirectories", "AppendData", "ReadExtendedAttributes", "WriteExtendedAttributes", "Traverse", "ExecuteFile", "DeleteSubdirectoriesAndFiles", "ReadAttributes", "WriteAttributes", "Write", "Delete", "ReadPermissions", "Read", "ReadAndExecute", "Modify", "ChangePermissions", "TakeOwnership", "Synchronize", "FullControl")]
        $FileSystemRights,

        [Parameter(Mandatory = $false)]
        [ValidateSet("This Folder Only", "This Folder Subfolders and Files", "This Folder and Subfolders", "This Folder and Files", "Subfolders and Files Only", "Subfolders Only", "Files Only")]
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
            Principal      = $Principal
            ForcePrincipal = $ForcePrincipal
        }
    }
    else
    {
        $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlEntry -Property @{
            AccessControlType = $AccessControlType
            FileSystemRights  = @($FileSystemRights)
            Inheritance       = $Inheritance
            Ensure            = $Ensure
        }
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
            Principal          = $Principal
            ForcePrincipal     = $ForcePrincipal
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
        [ValidateSet("Allow", "Deny")]
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
            Principal      = $Principal
            ForcePrincipal = $ForcePrincipal
        }
    }
    else
    {
        $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName AccessControlEntry -Property @{
            AccessControlType = $AccessControlType
            Rights            = @($RegistryRights)
            Inheritance       = $Inheritance
            Ensure            = $Ensure
        }
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName NTFSAccessControlList -Property @{
            Principal          = $Principal
            ForcePrincipal     = $ForcePrincipal
            AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntry)
        }
    }
    Return $CimAccessControlList
}

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

function Set-NewTempRegKeyAcl
{
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

function New-AuditAccessControlList
{
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Security.Principal.NTAccount]
        $Principal,

        [Parameter(Mandatory = $true)]
        [boolean]
        $ForcePrincipal,

        [Parameter(Mandatory = $false)]
        [System.Security.AccessControl.AuditFlags]
        $AuditFlags,

        [Parameter(Mandatory = $false)]
        [System.DirectoryServices.ActiveDirectoryRights]
        $ActiveDirectoryRights,

        [Parameter(Mandatory = $false)]
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]
        $InheritanceType,

        [Parameter(Mandatory = $false)]
        [guid]
        $InheritedObjectType,

        [Parameter(Mandatory = $false)]
        [guid]
        $ObjectType,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Absent', 'Present')]
        $Ensure
    )

    $activeDirectoryAuditRuleProperties = @{}
    switch ($PSBoundParameters.Keys)
    {
        'AuditFlags'
        {
            $activeDirectoryAuditRuleProperties.Add('AuditFlags', $AuditFlags.value__)
        }
        'ActiveDirectoryRights'
        {
            $activeDirectoryAuditRuleProperties.Add('ActiveDirectoryRights', @($ActiveDirectoryRights.value__))
        }
        'InheritanceType'
        {
            $activeDirectoryAuditRuleProperties.Add('InheritanceType', $InheritanceType.value__)
        }
        'InheritedObjectType'
        {
            $activeDirectoryAuditRuleProperties.Add('InheritedObjectType', $InheritedObjectType.Guid)
        }
        'ObjectType'
        {
            $activeDirectoryAuditRuleProperties.Add('ObjectType', $ObjectType.Guid)
        }
        'Ensure'
        {
            $activeDirectoryAuditRuleProperties.Add('Ensure', $Ensure)
        }
    }

    $nameSpace = 'root/Microsoft/Windows/DesiredStateConfiguration'
    $cimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $cimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    $adAccessControlListProperties = @{
        Principal      = $Principal.Value
        ForcePrincipal = $ForcePrincipal
    }

    $newCimInstanceParams = @{
        ClientOnly = $true
        Namespace  = $nameSpace
        ClassName  = 'ActiveDirectorySystemAccessControlList'
        Property   = $adAccessControlListProperties
    }

    if ($null -eq $ActiveDirectoryRights)
    {
        $cimAccessControlList += New-CimInstance @newCimInstanceParams
    }
    else
    {
        $newCimInstanceParams.ClassName = 'ActiveDirectoryAuditRule'
        $newCimInstanceParams.Property = $activeDirectoryAuditRuleProperties
        $cimAccessControlEntry += New-CimInstance @newCimInstanceParams

        $adAccessControlListProperties.Add('AccessControlEntry', [Microsoft.Management.Infrastructure.CimInstance[]]@($cimAccessControlEntry))
        $newCimInstanceParams.ClassName = 'ActiveDirectorySystemAccessControlList'
        $newCimInstanceParams.Property = $adAccessControlListProperties
        $cimAccessControlList += New-CimInstance @newCimInstanceParams
    }

    return $cimAccessControlList
}

<#
    .SYNOPSIS
    Creates an Access Control List Ciminstance

    .PARAMETER Principal
    Name of the principal which access rights are being managed

    .PARAMETER ForcePrincipal
    Used to force the desired access rule

    .PARAMETER AccessControlType
    States if the principal should be will be allowed or denied access

    .PARAMETER ActiveDirectoryRights
    What rights the principal is being given over an object

    .PARAMETER Inheritance
    The inheritance properties of the object being managed

    .PARAMETER InheritedObjectType
    The object type the inheritance property applies to

    .PARAMETER ObjectType
    The object type the ActiveDirectoryRights applies to

    .PARAMETER Ensure
    Either Present or Absent
#>

function New-ActiveDirectoryAccessControlList
{
    param
    (
        [Parameter(Mandatory = $true)]
        $Principal,

        [Parameter(Mandatory = $true)]
        [boolean]
        $ForcePrincipal,

        [Parameter()]
        [ValidateSet("Allow", "Deny")]
        [string]
        $AccessControlType,

        [Parameter()]
        [ValidateSet("AccessSystemSecurity", "CreateChild", "Delete", "DeleteChild", "DeleteTree", "ExtendedRight", "GenericAll", "GenericExecute", "GenericRead", "GenericWrite", "ListChildren", "ListObject", "ReadControl", "ReadProperty", "Self", "WriteDacl", "WriteOwner", "WriteProperty")]
        $ActiveDirectoryRights,

        [Parameter()]
        [ValidateSet("All", "Children", "Descendents", "None", "SelfAndChildren")]
        [String]
        $InheritanceType,

        [Parameter()]
        [string]
        $InheritedObjectType,

        [Parameter()]
        [string]
        $ObjectType,

        [Parameter(Mandatory = $true)]
        [ValidateSet("Absent", "Present")]
        $Ensure
    )

    $NameSpace = "root/Microsoft/Windows/DesiredStateConfiguration"
    $CimAccessControlList = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'
    $CimAccessControlEntry = New-Object -TypeName 'System.Collections.ObjectModel.Collection`1[Microsoft.Management.Infrastructure.CimInstance]'

    if ($null -eq $ActiveDirectoryRights)
    {
        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName ActiveDirectoryAccessControlList -Property @{
            Principal      = $Principal
            ForcePrincipal = $ForcePrincipal
        }
    }
    else
    {
        $CimAccessControlEntry += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName ActiveDirectoryAccessRule -Property @{
            AccessControlType     = $AccessControlType
            ActiveDirectoryRights = @($ActiveDirectoryRights)
            InheritanceType       = $InheritanceType
            InheritedObjectType   = $InheritedObjectType
            ObjectType            = $ObjectType
            Ensure                = $Ensure
        }

        $CimAccessControlList += New-CimInstance -ClientOnly -Namespace $NameSpace -ClassName ActiveDirectoryAccessControlList -Property @{
            Principal          = $Principal
            ForcePrincipal     = $ForcePrincipal
            AccessControlEntry = [Microsoft.Management.Infrastructure.CimInstance[]]@($CimAccessControlEntry)
        }
    }
    Return $CimAccessControlList
}

<#
    .SYNOPSIS
        Creates a new item and returns the associated Acl Object

    .PARAMETER Path
        Specifies the path of the location of the new item. Wildcard characters are permitted.

        You can specify the name of the new item in Name , or include it in Path .

    .PARAMETER Force
        Forces this function to create an item that writes over an existing read-only item. Implementation varies from
        provider to provider. For more information, see about_Providers. Even using the Force parameter, the function cannot
        override security restrictions.

    .PARAMETER DisableInheritance
        Disables inheritance from the newly created item.
#>
function New-TempAclItem
{
    [CmdletBinding()]
    [OutputType([System.Object])]
    Param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $Path,

        [Parameter()]
        [Switch]
        $Force,

        [Parameter()]
        [Switch]
        $DisableInheritance
    )

    $newTempAclItem = New-Item -Path $Path -Force:$Force
    $newTempAcl = $newTempAclItem.GetAccessControl()

    if ($PSBoundParameters.ContainsKey('DisableInheritance'))
    {
        $newTempAcl.SetAccessRuleProtection($true, $true)
        $newTempAclItem.SetAccessControl($newTempAcl)
        $newTempAcl = $newTempAclItem.GetAccessControl('Access')
    }

    return $newTempAcl
}
