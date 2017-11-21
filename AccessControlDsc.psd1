#
# Module manifest for module 'AccessControlDsc'
#
# Generated by: Adam Hynes
#
# Generated on: 8/21/2017
#

@{
    # Version number of this module.
    ModuleVersion = '0.9.0.0'

    # ID used to uniquely identify this module
    GUID = 'a544c26f-3f96-4c1e-8351-1604867aafc5'
    
    # Author of this module
    Author = 'Microsoft Corporation'
    
    # Company or vendor of this module
    CompanyName = 'Microsoft Corporation'
    
    # Copyright statement for this module
    Copyright = '(c) 2017 Microsoft. All rights reserved.'
    
    # Description of the functionality provided by this module
    Description = 'Provides an easy way to view and modify security descriptors for most securable objects in Windows, including files, folders, registry keys, services, printers, shares, processes, and more. Most actions possible from the ACL Editor GUI can be performed with this module.'
    
    # Minimum version of the Windows PowerShell engine required by this module
    PowerShellVersion = '4.0'
    
    # Name of the Windows PowerShell host required by this module
    # PowerShellHostName = ''
    
    # Minimum version of the Windows PowerShell host required by this module
    # PowerShellHostVersion = ''
    
    # Minimum version of the .NET Framework required by this module
    # DotNetFrameworkVersion = ''
    
    # Minimum version of the common language runtime (CLR) required by this module
    # CLRVersion = ''
    
    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''
    
    # Modules that must be imported into the global environment prior to importing this module
    # RequiredModules = @()
    
    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()
    
    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = ''
    
    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = 'PowerShellAccessControl.types.ps1xml'
    
    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = ''
    
    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()
    
    # Functions to export from this module
    FunctionsToExport = @()
    
    # Cmdlets to export from this module
    CmdletsToExport = @()
    
    # Variables to export from this module
    VariablesToExport = @()
    
    # Aliases to export from this module
    AliasesToExport = @()
    
    # List of all modules packaged with this module.
    # ModuleList = @()
    
    # List of all files packaged with this module
    # FileList = @()
    
    # Private data to pass to the module specified in RootModule/ModuleToProcess
    # PrivateData = ''
    
    # HelpInfo URI of this module
    # HelpInfoURI = ''
    
    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
PrivateData = @{
    
        PSData = @{
    
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('DesiredStateConfiguration', 'DSC', 'DSCResourceKit', 'DSCResource', 
                     'AccessControlDsc', 'DACL', 'SACL')
    
            # A URL to the license for this module.
            LicenseUri = 'https://github.com/PowerShell/AccessControlDsc/blob/master/LICENSE'
    
            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/PowerShell/AccessControlDsc'
    
            # A URL to an icon representing this module.
            # IconUri = ''
    
            # ReleaseNotes of this module
            #ReleaseNotes = ''
        } # End of PSData hashtable
    
    } # End of PrivateData hashtable
    
}
