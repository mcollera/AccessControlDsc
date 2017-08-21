master: [![Build status](https://ci.appveyor.com/api/projects/status/fg26tpfjv7odbgbu/branch/master?svg=true)](https://ci.appveyor.com/project/PowerShell/AccessControlDsc/branch/master)  
dev: [![Build status](https://ci.appveyor.com/api/projects/status/fg26tpfjv7odbgbu/branch/Dev?svg=true)](https://ci.appveyor.com/project/PowerShell/AccessControlDsc/branch/dev)

# AccessControlDsc

The **AccessControlDsc** module allows you to configure and manage access control on windows based objects.

This project has adopted the [Microsoft Open Source Code of Conduct](
  https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](
  https://opensource.microsoft.com/codeofconduct/faq/) 
or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions 
or comments.

## Contributing
Please check out common DSC Resources [contributing guidelines](
  https://github.com/PowerShell/DscResources/blob/master/CONTRIBUTING.md).

## Resources

* [AccessControlEntry](#AccessControlEntry): Provides a mechanism to manage access control entries. 

* [SecurityDescriptor](#SecurityDescriptor): Provides a mechanism to manage security descriptors. 

* [SecurityDescriptorSddl](#SecurityDescriptorSddl): Provides a mechanism manage sddl.

### AccessControlEntry
Provides a mechanism to manage access control entries.
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] Path _(Key)_**: The .

* **[String] ObjectType _(Key)_**: The . 
{ File | Directory | RegistryKey | Service | WmiNamespace | Cert | AD }.

* **[String] Ensure _(Write)_**: Indicates whether the ACE is present or absent. 
Defaults to Present. { *Present* | Absent }.

* **[String] AceType _(Write)_**: The 
{ AccessAllowed | AccessDenied | SystemAudit }.

* [Boolean] AuditSuccess _(Write)_: The

* [Boolean] AuditFailure _(Write)_: The

* [String] Principal _(Write)_: The

* [UInt32] AccessMask _(Write)_: The

* [String] AppliesTo _(Write)_: The

* [Boolean] OnlyApplyToThisContainer _(Write)_: The

* [Boolean] Specific _(Write)_: The



#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Set Access Control Entry](
  https://github.com/PowerShell/AccessControlDsc/blob/master/Examples/Sample_AccessControlEntry.ps1)

### SecurityDescriptor
Provides a mechanism to manage security descriptors. 
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] Path _(Key)_**: The  

* **[String] ObjectType _(Key)_**: The .
{ File | Directory | RegistryKey | Service | WmiNamespace | Cert | AD }.

* [String] Owner _(Key)_: The .

* [String] Group _(Key)_: The .

* [String] Access _(Key)_: The .

* [String] AccessInheritance _(Key)_: The .
{ Enabled | Disabled }.

* [String] Audit _(Key)_: The .

* [String] AuditInheritance _(Key)_: The .
{ Enabled | Disabled }.



#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Set Security Descriptor](
  https://github.com/PowerShell/AccessControlDsc/blob/master/Examples/Sample_SecurityDescriptor.ps1)

### SecurityDescriptorSddl
Provides a mechanism to restore an audit policy backup.
This resource works on Nano Server.

#### Requirements

None

#### Parameters

* **[String] Path _(Key)_**: The  

* **[String] ObjectType _(Key)_**: The .
{ File | Directory | RegistryKey | Service | WmiNamespace | Cert | AD }.

* [String] Sddl _(Key)_: The .


#### Read-Only Properties from Get-TargetResource

None

#### Examples

* [Apply SDDL](
  https://github.com/PowerShell/AccessControlDsc/blob/master/Examples/Sample_SecurityDescriptorSddl.ps1)

## Versions

### Unreleased

* Initial release with the following resources:
 
  * AccessControlEntry
  * SecurityDescriptor
  * SecurityDescriptorSddl

### 1.0.0.0
