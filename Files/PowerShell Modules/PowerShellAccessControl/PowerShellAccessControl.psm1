<#
Version 3.0 BETA notes:
  - The help is not finished for the module
  - There are some examples of the new functionality, but there will be mroe
  - More will be added/fixed before 3.0 is released

Version 3.1 (or later) features:
  - Get-EffectiveAccess will allow additional groups, user claims, and device claims
  - Get-EffectiveAccess will take CAP and share permissions into account
  - DSC resources will allow CAP to be associated or cleared from an SD
  - Set-MandatoryIntegrityLevel
  - DSC resources will be able to set MILs
  - New-AccessControlEntry will be able to create CallbackAce objects (-Condition parameter??)
#>
<#
New in 3.0:
  - New-AdaptedAcl re-written. Now supports ObjectAces. Major changes, so other functions have been modified:
      * Synthetic properties added to original CommonAce or ObjectAce. Check this in v2
      * This required changes to formatting, so now FT and FL show a Principal field instead 
        of an IdentityReference. There is a Principal and SecurityIdentifier property for each 
        ACE (this is potentially a breaking change)
      * Original AccessMask is left untouched, but there is now an AccessMaskDisplay property 
        (not always true; generic mappings now modify access mask)
      * ACEs with the same properties (except access mask) are now merged (like the ACL Editor does)
      * Generic rights mapping (see Get-Acl vs Get-SD for C:\WINDOWS, C:\WINDOWS\tracing, HKLM:\SOFTWARE)
  - New-AccessControlEntry (and any of the *-AccessControlEntry functions that depend on it) can now support 
    remote accounts. Just put the account in the '[COMPUTER]\[USER]' format. It can also take SIDs now, too 
    (string or SecurityIdentifier object)

    Removed -User and -Group aliases for New-Ace. Group alias was causing issues when SD was piped to Add/Remove-Ace (SDs have a
    'Group' property, so it was being bound to principal if the user forgot to add the -Principal (or one of its aliases) as
    a named parameter
  - If a SID can't be translated locally, the SDObjectType and SDPath are checked to see if it is an AD object, 
    in which case the domain is pulled from the SDPath and that is used as the remote computer name to attempt 
    translation, or if the SDPath is in the \\computername\path format, in which case the computer name is pulled 
    and that is used to attempt translation. If translation still can't happen, the SID object's ToString method 
    is overloaded and that is assigned to the principal.
  - Get-AccessControlEntry:
      * Can handle Native .NET SDs (from Get-Acl) - This is b/c Get-SecurityDescriptor will convert a native .NET
        SD into an "adapted SD"
      * Can work with ObjectAceTypes in GUID or string format
      * Because Get-Acl inputs are now converted to PAC objects, New-AdaptedAcl is used directly instead of using the 'Access' property. Also, 'Access' property
        will start using Get-AccessControlEntry
  - New-AccessControlEntry creates AD rules
  - Set-SD can now handle native .NET SDs
  - Long file name support (over 260 characters)
  - Callback ACEs partially work. Condition isn't current displayed, but that will be easy enough to get (just convert ACE to SDDL and
    grab the conditional string from that)
  - Get-Ace -AuditSuccess and -AuditFailure can't be used at the same time. To see only audits, use -AceType SystemAudit
#>

<#
Dynamic parameters have been removed because of a bug in Get-Help displaying the syntax: https://connect.microsoft.com/PowerShell/feedback/details/397832/dynamicparam-not-returned-when-aliased
(Get/Add/Remove)-AccessControlEntry all shared the parameters of New-AccessControlEntry (which had some dynamic parameters of its own). This was
b/c in early versions of the module, the parameters were changing (and before 3.0, I knew that I wanted to add AD parameters). The param blocks
have reached a point to where they are pretty stable, so it's time to declare all of them as real params.
#>

#region Helper files/types
# Read helper functions:
. "$PSScriptRoot\PowerShellAccessControlHelperFunctions.ps1"
. "$PSScriptRoot\PowerShellAccessControlPInvokeSignatures.ps1"
. "$PSScriptRoot\PowerShellAccessControlAccessMaskEnumerations.ps1"
#endregion

#region Module-wide variables
# Store a list of access mask enumerations, which will be used for dynamic parameters (ignore ActiveDirectoryRights--it is special and has its own param set in New-AccessControlEntry):
$__AccessMaskEnumerations = [System.AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -eq $false } | % { $_.GetTypes() } | ? { $_.FullName -match "^PowerShellAccessControl\..*(?<!ActiveDirectory)Rights$" }

# Some constants to help out with formatting (and to help functions know what types of objects
# they're dealing with since module doesn't create a true custom .NET object yet):
$__AdaptedSecurityDescriptorTypeName = "PowerShellAccessControl.Types.AdaptedSecurityDescriptor"
$__AdaptedAceTypeName = "PowerShellAccessControl.Types.AdaptedAce"
$__EffectiveAccessTypeName = "PowerShellAccessControl.Types.EffectiveAccess"
$__EffectiveAccessListAllTypeName = "PowerShellAccessControl.Types.EffectiveAccessListAllPermissions"

# GetSecurityItem and SetSecurityItem need System.Security.AccessControl.ResourceType objects to know what
# to work on. The following type is used when GetSecurityInfo and SetSecurityInfo won't be able to work
# with the security descriptor. This module will know how to handle these resources.
$__PowerShellAccessControlResourceTypeName = "ProviderDefined"

$__PartOfDomain = Get-WmiObject Win32_ComputerSystem -Property PartOfDomain | select -exp PartOfDomain
[version] $__OsVersion = Get-WmiObject Win32_OperatingSystem -Property Version | select -exp Version

# Change this to prevent -Apply switch from always causing a prompt (if -Force or -Confirm:$false aren't supplied)
$__ConfirmImpactForApplySdModification = [System.Management.Automation.ConfirmImpact]::High

# Used for Get-AccessControlEntry; number was pulled out of my head
$__MaxFilterConditionCount = 200

# These are used for AD objects. Hash tables are used for caching, and will be populated as the functionality is requested by
# the user

# The names for the hts and ValidateSet attributes are dependent on the Get-SdObjectAceType function. It is aware of the
# naming convention used, so if these are renamed, fix that (and the functions that populate the hash tables)
$__DsPropertyTable = @{}
$__DsPropertySetTable = @{}
$__DsValidatedWriteTable = @{}
$__DsClassObjectTable = @{}
$__DsExtendedRightTable = @{}
$__DsPropertyToPropertySetTable = @{}
$__GroupedPropertyCache = @{}

# These are used with the Get ObjectAce functions (the attributes are cached so they're only populated once per session,
# and only after they're needed for the first time)
$__PropertyValidateSet = $null # New-Object System.Management.Automation.ValidateSetAttribute "Property"
$__PropertySetValidateSet = $null # New-Object System.Management.Automation.ValidateSetAttribute "PropertySet"
$__ValidatedWriteValidateSet = $null # New-Object System.Management.Automation.ValidateSetAttribute "ValidatedWrite"
$__ExtendedRightValidateSet = $null # New-Object System.Management.Automation.ValidateSetAttribute "ExtendedRight"
$__ClassObjectValidateSet = $null # New-Object System.Management.Automation.ValidateSetAttribute "Class"
#endregion

#region Settings
# Thinking of making these configurable through a function; need to figure out where to save per-user settings...
$__ObjectsToMergeAces = @(
    "FileObject"
    "RegistryKey"
    "RegistryWow6432Key"
)
$__GetInheritanceSource = $true
$__DontTranslateGenericRights = $false
#endregion

#.ExternalHelp PowerShellAccessControl.Help.xml
function New-AccessControlEntry {

<#
DESIGN NOTES:
The GenericAccessMask param set parameters can come in through the pipeline by propertyname. This enables the following pattern:
Get-AccessControlEntry | Add-AccessControlEntry -SDObject <object>
Get-AccessControlEntry <-FilteringParams> | Remove-AccessControlEntry

AppliesTo and OnlyApplytoThisContainer can come from the pipeline now. AppliesTo will beat AceFlags if their values conflict. AceFlags
can be used to provide AuditFlags and Inheritance/Propagation flags (WMI ACE objects use AceFlags)

#>

    [CmdletBinding(DefaultParameterSetName="FileRights")]
    param(
        # 
        [Parameter(Position=0, ValueFromPipelineByPropertyName=$true)]
        [ValidateSet(
            "AccessAllowed",
            "AccessDenied",
            "SystemAudit"
        )]
        [string] $AceType = "AccessAllowed",
        [Parameter(Mandatory=$true, Position=1, ValueFromPipelineByPropertyName=$true)]
        [Alias('IdentityReference','SecurityIdentifier')]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName='FileRights')]
        [Alias('FileSystemRights')]
        [System.Security.AccessControl.FileSystemRights] $FileRights,
        [Parameter(Mandatory=$true, ParameterSetName='FolderRights')]
        [System.Security.AccessControl.FileSystemRights] $FolderRights,
        [Parameter(Mandatory=$true, ParameterSetName='RegistryRights')]
        [System.Security.AccessControl.RegistryRights] $RegistryRights,
        [Parameter(Mandatory=$true, ParameterSetName='ActiveDirectoryRights')]
        [PowerShellAccessControl.ActiveDirectoryRights] $ActiveDirectoryRights,
        [Parameter(Mandatory=$true, ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [int] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [PowerShellAccessControl.AppliesTo] $AppliesTo = "Object",
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [switch] $OnlyApplyToThisContainer,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $ObjectAceType,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $InheritedObjectAceType,
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.AceFlags] $AceFlags,
        [Parameter(ParameterSetName='GenericAccessMask')]
        [Parameter(ParameterSetName='FileRights')]
        [Parameter(ParameterSetName='FolderRights')]
        [Parameter(ParameterSetName='RegistryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRights')]
        [switch] $GenericAce
    )

    dynamicparam {

        # Two sets of dynamic parameters are created:
        #    1. Create a dynamic parameter for each of the access mask enumerations contained in the $__AccessMaskEnumerations
        #       variable
        #    2. If -AceType is SystemAudit, create -AuditSuccess and -AuditFailure parameters


        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        foreach ($Enumeration in $__AccessMaskEnumerations) {

            $ParamAttributes = New-Object System.Management.Automation.ParameterAttribute
            $ParamAttributes.ParameterSetName = "Generic{0}" -f $Enumeration.Name
            $ParamAttributes.Mandatory = $true
            #$ParamAttributes.ValueFromPipelineByPropertyName = $true

            # Create the attribute collection (PSv3 allows you to simply cast a single attribute
            # to this type, but that doesn't work in PSv2)
            $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]  # needed for v2
            $AttribColl.Add($ParamAttributes)

            $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                $Enumeration.Name,
                $Enumeration,
                $AttribColl #[System.Collections.ObjectModel.Collection[System.Attribute]] $ParamAttributes
            )
            $DynParamDictionary.Add($Enumeration.Name, $DynamicParameter)
        }

        if ($PSBoundParameters.AceType -eq "SystemAudit") {

            foreach ($ParameterName in "AuditSuccess","AuditFailure") {
                $ParamAttributes = New-Object System.Management.Automation.ParameterAttribute

                # Create the attribute collection (PSv3 allows you to simply cast a single attribute
                # to this type, but that doesn't work in PSv2)
                $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]  # needed for v2
                $AttribColl.Add($ParamAttributes)
                $AttribColl.Add([System.Management.Automation.AliasAttribute] [string[]] ($ParameterName -replace "Audit"))

                $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                    $ParameterName,
                    [switch],
                    $AttribColl
                )
                $DynParamDictionary.Add($ParameterName, $DynamicParameter)
            }
        }
      
        # Return the dynamic parameters
        $DynParamDictionary
    }

    process {

        $AceType = [System.Security.AccessControl.AceQualifier] $AceType
        $AccessRightsParamName = $PSCmdlet.ParameterSetName -replace "^Generic", ""
        $AccessRightsParamName = $AccessRightsParamName -replace "ObjectAceType$", "" # Special paramset so that AccessMask isn't required

        if ($AccessRightsParamName -eq "ActiveDirectoryRights") {
            $AccessMaskEnumeration = [PowerShellAccessControl.ActiveDirectoryRights]
        }
        else {
            $AccessMaskEnumeration = $PSBoundParameters[$AccessRightsParamName].GetType()
        }

        #region Get Inheritance and Propagation flags       
        if (-not $PSBoundParameters.ContainsKey("AppliesTo")) {
            if ($PSBoundParameters.ContainsKey("AceFlags") -and $AceFlags.value__ -band [System.Security.AccessControl.AceFlags]::InheritanceFlags.value__) {
                # AceFlags contains inheritance/propagation info, so get the AppliesTo from that
                $InheritanceFlags = $PropagationFlags = 0
                foreach ($CurrentFlag in "ContainerInherit", "ObjectInherit") {
                    if ($AceFlags.value__ -band ([int][System.Security.AccessControl.AceFlags]::$CurrentFlag)) {
                        $InheritanceFlags = $InheritanceFlags -bor [System.Security.AccessControl.InheritanceFlags]::$CurrentFlag
                    }
                }
                foreach ($CurrentFlag in "NoPropagateInherit","InheritOnly") {
                    if ($AceFlags.value__ -band ([int][System.Security.AccessControl.AceFlags]::$CurrentFlag)) {
                        $PropagationFlags = $PropagationFlags -bor [System.Security.AccessControl.PropagationFlags]::$CurrentFlag
                    }
                }

                # This is extra work b/c inheritance and propagation flags will be obtained from $AppliesTo again in a minute,
                # but AceFlags coming in is actually pretty rare, so I don't mind the wasted work on the function's part
                $AppliesTo = GetAppliesToMapping -InheritanceFlags $InheritanceFlags -PropagationFlags $PropagationFlags
                $OnlyApplyToThisContainer = [bool] ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)
            }
            else {
                # ACEs for different types of objects have different default "AppliesTo". If -AppliesTo param wasn't specified,
                # then figure out the default. Function needs to know the access mask enumeration and whether or not the ACE
                # will belong to an SD that is a container. We can't know that for sure, but we can make assumptions based on
                # the parameter set name:
                $DefaultAppliesToParams = @{
                    AccessMaskEnumeration = $AccessMaskEnumeration
                }
                if ("RegistryRights", "GenericWmiNamespaceRights", "ActiveDirectoryRights", "ActiveDirectoryRightsObjectAceType", "FolderRights" -contains $PSCmdlet.ParameterSetName) {
                    $DefaultAppliesToParams.IsContainer = $true
                }

                $AppliesTo = GetDefaultAppliesTo @DefaultAppliesToParams
            }
        }

        # Convert $AppliesTo and $OnlyAppliesToThisContainer to separate
        # inheritance flags and propagation flags enums:
        $AppliesToFlags = GetAppliesToMapping -AppliesTo $AppliesTo
        $InheritanceFlags = $AppliesToFlags.InheritanceFlags
        $PropagationFlags = $AppliesToFlags.PropagationFlags

        if ($OnlyApplyToThisContainer) {
            [System.Security.AccessControl.PropagationFlags] $PropagationFlags = $PropagationFlags -bor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
        }

        #endregion 

        # Make sure -Principal parameter is an identity reference (NTAccount or SID)
        $Principal = $Principal | ConvertToIdentityReference -ErrorAction Stop -ReturnSid

        #region Get Audit flags
        # Check to see if this should be an audit ACE. If so, set up the AuditFlags (these will be used 
        # as is when File or Registry SACL ACEs are used, and will be used to build the proper flags for 
        # a generic ACE)
        if ($AceType -eq [System.Security.AccessControl.AceQualifier]::SystemAudit) {
            $AuditFlags = @()

            # Success/Failure audits may have been specified through parameters (interactive use)
            if ($PSBoundParameters.AuditSuccess) { $AuditFlags += "Success" }
            if ($PSBoundParameters.AuditFailure) { $AuditFlags += "Failure" }


            # Or Success/Failure audits may have been specified through AceFlags (usually happens
            # when another ACE is fed to New-AccessControlEntry through pipeline.
            if ([int] $PSBoundParameters.AceFlags -band [System.Security.AccessControl.AceFlags]::SuccessfulAccess) { $AuditFlags += "Success" }
            if ([int] $PSBoundParameters.AceFlags -band [System.Security.AccessControl.AceFlags]::FailedAccess) { $AuditFlags += "Failure" }

            if ($AuditFlags) {
                $AuditFlags = $AuditFlags -as [System.Security.AccessControl.AuditFlags]
            }
            else {
                # You've got to have some audit flags
                throw "You must specify audit flags when AceType is SystemAudit. Please use one or more of the following parameters: -AuditSuccess, -AuditFailure"
            }
        }
        else {
            # If this ACE will be a native .NET class ACE, then no need to worry about this variable. If this
            # is going to be a generic ACE, though, the $AuditFlags, $InheritanceFlags, and $PropagationFlags
            # will all be combined into a single $AceType variable, so we need to define $AuditFlags:
            $AuditFlags = 0
        }
        #endregion

        # Assign numeric access rights
        $AccessRights = [int] $PSBoundParameters[$AccessRightsParamName]

        # Finalize parameters to the New-Object call after switch statement:
        switch -Regex ($PSCmdlet.ParameterSetName) {
            "^(File|Folder)Rights$" {
                $AccessControlObject = "System.Security.AccessControl.FileSystem{0}Rule"
            }

            "^RegistryRights$" {
                $AccessControlObject = "System.Security.AccessControl.Registry{0}Rule"
            }
    
            "^ActiveDirectoryRights" {
                $AccessControlObject = "System.DirectoryServices.ActiveDirectory{0}Rule"

                # These actions are shared between both AD rule and GenericAce rule creations:

                # We need GUIDs for ObjectAceType and InheritedObjectAceType. The parameters can come
                # in as a GUID, a string (string form of GUID, or a string to search on), or a PSObject
                # returned from Get-ADObjectAceGuid. The code to fix both are the same, except the variable
                # name changes. For that reason, we just use Get/Set variable cmdlets to do the same thing
                # for both:
                foreach ($AceTypeName in "ObjectAceType", "InheritedObjectAceType") {
                    $AceTypeValue = Get-Variable -Name $AceTypeName -ValueOnly -Scope 0 -ErrorAction SilentlyContinue

                    if ($AceTypeValue -is [array]) {
                        Write-Error "$AceTypeName parameter takes a single value"
                        return
                    }

                    if ($AceTypeValue) {
                        # If this isn't a GUID, then do a lookup using Get-AdObjectAceGuid helper function. If it is a GUID, no
                        # lookup necessary (assume user or ConvertToCommonAce knows what it wants when GUID was specified)

                        $AceTypeObject = if ($AceTypeValue -is [PSObject] -and $AceTypeValue.Guid -is [guid]) {
                            New-Object PSObject -Property @{
                                Guid = $AceTypeValue.Guid
                            }
                        }
                        else {
                            try {
                                # Attempt to convert to a GUID (since string GUID may have been passed):
                                New-Object PSObject -Property @{
                                    Guid = [guid] $AceTypeValue
                                }
                            }
                            catch {
                                # Conversion failed, so attempt lookup via name
                                $Params = @{}
                                $Params.Name = "^{0}$" -f $AceTypeValue
                                if ($AceTypeName -eq "InheritedObjectAceType") {
                                    # This should be limited to ClassObjects (I think)
                                    $Params.TypesToSearch = "ClassObject"
                                }

                                try {
                                    Get-ADObjectAceGuid -ErrorAction Stop @Params | Select-SingleObject
                                }
                                catch {
                                    Write-Error $_
                                    return
                                }
                            }
                        }

                        $AceTypeValue = $AceTypeObject | select -ExpandProperty Guid

                        # If ObjectAceType was specified, this next check will make sure that the access mask contains the right access depending on the
                        # object type:

                        if ($AceTypeName -eq "ObjectAceType") {
                            # Find out what the access mask must contain ($ValidAccessMask) and what to
                            # set it to if no access mask was provided ($DefaultAccessMask)
                            switch -regex ($AceTypeObject.Type) {
                            
                                "Property(Set)?" {
                                    $ValidAccessMask = [PowerShellAccessControl.ActiveDirectoryRights] "ReadProperty, WriteProperty"
                                    $DefaultAccessMask = [PowerShellAccessControl.ActiveDirectoryRights]::ReadProperty
                                    break
                                }

                                "ExtendedRight" {
                                    $DefaultAccessMask = $ValidAccessMask = [System.DirectoryServices.ActiveDirectoryRights]::ExtendedRight
                                    break
                                }

                                "ValidatedWrite" {
                                    $DefaultAccessMask = $ValidAccessMask = [System.DirectoryServices.ActiveDirectoryRights]::Self
                                    break
                                }

                                "ClassObject" {
                                    $ValidAccessMask = [System.DirectoryServices.ActiveDirectoryRights] "CreateChild, DeleteChild"
                                    $DefaultAccessMask = [System.DirectoryServices.ActiveDirectoryRights]::CreateChild
                                    break
                                }

                                default {
                                    # Don't do anything
                                    $ValidAccessMask = $ActiveDirectoryRights
                                    $DefaultAccessMask = $ActiveDirectoryRights
                                }
                            }

                            if (-not ($AccessRights -band $ValidAccessMask)) {
                                if (-not $ValidAccessMask) {
                                    Write-Error "Please provide access rights to the -ActiveDirectoryRights parameter."
                                    return
                                }
                                elseif ($ValidAccessMask -ne $DefaultAccessMask) {
                                    # If this happens, that means there's more than one access right implied
                                    # by the ObjectAceType. Let the user know that we made a choice for them,
                                    # and that they can fix that choice if they like
                                    Write-Warning ("Valid access rights for {0} {1} are {2}. Since neither was supplied to the -ActiveDirectoryRights parameter, the {3} right was added to the access mask. If this is incorrect, please use the -ActiveDirectoryRights parameter." -f $AceTypeObject.Name, $AceTypeObject.Type, $ValidAccessMask, $DefaultAccessMask)
                                }

                                $AccessRights = $AccessRights -bor $DefaultAccessMask
                            }
                        }
                    }
                    else {
                        $AceTypeValue = [guid]::Empty
                    }

                    Set-Variable -Name $AceTypeName -Value $AceTypeValue -Scope 0
                }
            }

            #region Build constructor array for non-generic ACEs
            { ("Filerights", "FolderRights", "RegistryRights", "ActiveDirectoryRights", "ActiveDirectoryRightsObjectAceType" -contains $_) -and
              (-not $GenericAce) } {

                # These three scenarios use the exact same actions for the ACE type/flags, so
                # might as well handle them together. Constructing the rule is also identical
                # besides changing the object type. all of that was handled in the previous
                # two blocks, though.
                if ($AceType -eq [System.Security.AccessControl.AceQualifier]::SystemAudit) {
                    $Flags = $AuditFlags
                }
                elseif ($AceType -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed) {
                    $Flags = [System.Security.AccessControl.AccessControlType]::Allow
                }
                elseif ($AceType -eq [System.Security.AccessControl.AceQualifier]::AccessDenied) {
                    $Flags = [System.Security.AccessControl.AccessControlType]::Deny
                }
                else {
                    # Only other enum option is SystemAlarm, and that was checked on earlier, so this
                    # shouldn't ever happen:
                    throw "Unknown ACE qualifier"
                }

                if ($_ -match "ActiveDirectoryRights") {
                    # AD rule constructors are slightly different than the other rule types:
                    $AdSecurityInheritance = GetAppliesToMapping -ADAppliesTo $AppliesTo -OnlyApplyToThisADContainer:$OnlyApplyToThisContainer

                    $Arguments = @(
                        $Principal
                        $AccessRights
                        $Flags
                        $ObjectAceType
                        $AdSecurityInheritance
                        $InheritedObjectAceType
                    )
                }
                else {
                    # All other rule types share the same constructor
                    $Arguments = @( 
                        $Principal         # System.String
                        $AccessRights      # System.Security.AccessControl.RegistryRights or FileSystemRights
                        $InheritanceFlags  # System.Security.AccessControl.InheritanceFlags
                        $PropagationFlags  # System.Security.AccessControl.PropagationFlags
                        $Flags             # System.Security.AccessControl.AccessControlType or AuditFlags
                    )
                }
            }
            #endregion

            #region Build constructor array for generic ACEs
            { $_ -like "Generic*" -or $GenericAce } {

                # Always a CommonAce, no matter if it is for DACL or SACL (AceQualifier distinguishes this)
                $AccessControlObject = "System.Security.AccessControl.CommonAce"

                # Instead of inheritance, propagation, and audit flags being specified separately to the constructor,
                # all flags are combined into the AceFlags enumeration.
                # Start with $InheritanceFlags and $PropagationFlags first:
                [int] $AceFlags = [System.Security.AccessControl.AceFlags] (($InheritanceFlags.ToString() -split ", ") + ($PropagationFlags.ToString() -split ", "))

                # And finish with the $AuditFlags:
                if ($AuditFlags) {
                    # Convert the audit flag only enumeration into the right values for AceType enumeration
                    if ($AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) {
                        $AceFlags += [System.Security.AccessControl.AceFlags]::SuccessfulAccess.value__
                    }
                    if ($AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure) {
                        $AceFlags += [System.Security.AccessControl.AceFlags]::FailedAccess.value__
                    }
                }

                # These params are common between an ObjectAce and a CommonAce
                $Arguments = @( $AceFlags    # System.Security.AccessControl.AceFlags
                                $AceType     # System.Security.AccessControl.AceQualifier
                                $AccessRights
                                $Principal
                              )


                # If Object ACE guids were specified, we're going to create an ObjectAce instead
                # of a CommonAce
                if ($PSBoundParameters.ContainsKey("ObjectAceType") -or $PSBoundParameters.ContainsKey("InheritedObjectAceType")) {
                    $AccessControlObject = "System.Security.AccessControl.ObjectAce"

                    $ObjectAceFlags = 0
                    if ($PSBoundParameters.ContainsKey("ObjectAceType") -and $ObjectAceType -ne [guid]::Empty) {
                        $ObjectAceFlags = $ObjectAceFlags -bor [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent
                    }
                    else {
                        $ObjectAceType = [guid]::Empty
                    }

                    if ($PSBoundParameters.ContainsKey("InheritedObjectAceType") -and $InheritedObjectAceType -ne [guid]::Empty) {
                        $ObjectAceFlags = $ObjectAceFlags -bor [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent
                        # $ObjectAceType guid already defined from parameters
                    }
                    else {
                        $InheritedObjectAceType = [guid]::Empty
                    }

                    $Arguments += $ObjectAceFlags
                    $Arguments += $ObjectAceType
                    $Arguments += $InheritedObjectAceType
                }

                # These params are common between an ObjectAce and a CommonAce; they are currently not used, but may
                # be in the future
                $Arguments += $false  # isCallback?
                $Arguments += $null   # opaque data
            }
            #endregion

            default {
                Write-Error "Unknown ParameterSetName" 
                return
            }

        }

        # Create the ACE object
        if ($AuditFlags) {
            $AuditOrAccess = "Audit"
        }
        else {
            $AuditOrAccess = "Access"
        }
        $AccessControlObject = $AccessControlObject -f $AuditOrAccess
        New-Object -TypeName $AccessControlObject -ArgumentList $Arguments
    }
}

# Since dynamic parameters have been removed, get a list of New-Ace parameters for the functions
# that need to call New-Ace internally (they need to have a list of valid params to build hash
# tables for splatting
$__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
    Get-Member -MemberType Properties | 
    Select-Object -ExpandProperty Name
$__NewAceParameterNames = Get-Command New-AccessControlEntry -ArgumentList SystemAudit | select -exp Parameters | select -exp Keys | where { $__CommonParameterNames -notcontains $_ }

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-AccessControlEntry {

    [CmdletBinding(DefaultParameterSetName='__AllParameterSets')]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [Alias('Path')]
        # An object that contains a security descriptor
        $InputObject,
        [switch] $Audit,
        [switch] $Inherited,
        [switch] $NotInherited,
        [switch] $Specific,
        [object[]] $ObjectAceType,
        [object[]] $InheritedObjectAceType,
        [System.Security.AccessControl.AuditFlags] $AuditFlags,
# Old dynamic params start here:
        [ValidateSet(
            "AccessAllowed",
            "AccessDenied",
            "SystemAudit"
        )]
        [string[]] $AceType = "AccessAllowed",
        [Alias('IdentityReference','SecurityIdentifier')]
        [string[]] $Principal,
        [Alias('FileSystemRights')]
        [System.Security.AccessControl.FileSystemRights] $FileRights,
        [System.Security.AccessControl.FileSystemRights] $FolderRights,
        [System.Security.AccessControl.RegistryRights] $RegistryRights,
        [PowerShellAccessControl.ActiveDirectoryRights] $ActiveDirectoryRights,
        [PowerShellAccessControl.LogicalShareRights] $LogicalShareRights,
        [PowerShellAccessControl.PrinterRights] $PrinterRights,
        [PowerShellAccessControl.WmiNamespaceRights] $WmiNameSpaceRights,
        [PowerShellAccessControl.ServiceAccessRights] $ServiceAccessRights,
        [PowerShellAccessControl.ProcessAccessRights] $ProcessAccessRights,
        [int] $AccessMask,
        [PowerShellAccessControl.AppliesTo] $AppliesTo,
        [switch] $OnlyApplyToThisContainer
    )

<# 
    dynamicparam {
        $DynamicParams = GetNewAceParams -RemoveMandatoryAttribute -ConvertTypesToArrays

        # These params have their own parameter sets that shouldn't be enforced on this
        # function. They've been added to the param block, so they need to be removed
        # from the dynamic param dictionary.
        foreach ($ParamToRemove in "ObjectAceType", "InheritedObjectAceType") {
            [void] $DynamicParams.Remove($ParamToRemove)
        }

        $DynamicParams
        
    }
#>

    begin {
        # This function is going to call New-AdaptedAcl on a security descriptor object. New-AdaptedAcl
        # takes switch parameters for -Dacl and -Sacl (or both). Build a hash table based on -AceType
        # sent to this function that can be splatted to New-AdaptedAcl (since that can save work that
        # New-AdaptedAcl might have to do otherwise)
        $AdaptedAclParams = @{
            GetInheritanceSource = $__GetInheritanceSource
            DontTranslateGenericRights = $__DontTranslateGenericRights
        }

        if (-not $PSBoundParameters.AceType) {
            # No AceType specified, so show both DACL and SACL
            $AdaptedAclParams.Dacl = $true
            $AdaptedAclParams.Sacl = $true
        }
        else {
            if ($PSBoundParameters.AceType -match "^Access") {
                $AdaptedAclParams.Dacl = $true
            }

            if ($PSBoundParameters.AceType -match "^SystemAudit") {
                $AdaptedAclParams.Sacl = $true
            }
        }

        #region Build the filter array
        # Any parameter that New-AccessControlEntry has can be used to build the ACE filter,
        # so get each of the parameter names:
#        $NewAceParamNames = (GetNewAceParams).GetEnumerator() | select -exp Key
        $NewAceParamNames = $__NewAceParameterNames
        $NewAceParamNames += "Inherited", "NotInherited", "AuditFlags"   # Add params defined for the function but not in New-AccessControlEntry

        $Filter = @()
        foreach ($ParamName in $NewAceParamNames) {
            $CurrentFilter = @()
            foreach ($Object in $PSBoundParameters.$ParamName) {
                if ($Object -eq $null) { continue } # Ignore nulls

                switch -regex ($ParamName) {
                    Principal {
                        # Add Principal condition to the Where-Object SB;  using regular expression to search
                        #  "^(.*\\)?" and "$" are added to string to allow for an optional domain before the 
                        #  username.
                        #
                        # There is no need for different behavior when -Specific is used because the ^ and $
                        # achors are already being used. User can still use * wildcard.
                        # 
                        # Two replace operations:
                        #  1. Replaces a * with a .* so that regex will behave the way that * does with the 
                        #     -like operator
                        #  2. Escape any single backslashes with double backslashes
                        $CurrentFilter += '$_.Principal -match "^(.*\\)?{0}$"' -f (($Object | ModifySearchRegex) -replace "(?<!\\)\\(?!\\)", '\$0')  # Replace single backslash w/ double backslash. This present problems if user presents a regex that has a character escaped...
                        break
                    }

                    "ObjectAceType$" {
                        # Object ace. Because Get-ADObjectAceGuid helper function returns an object, need to
                        # check to see what type this parameter is

                        if ($Object -is [PSObject] -and $Object.Guid -is [guid]) {
                            # Assume object came from Get-AdObjectAceGuid
                            $Object = $Object.Guid
                        }
                        elseif ($Object -as [guid]) {
                            # User passed in a GUID object, or a string representation of a GUID
                            $Object = $Object -as [guid]
                        }


                        # We need to build a filter string. The left side of the comparison operation
                        # will differ depending on whether or not a GUID or string was passed, but it
                        # will always start the same:
                        $LeftSide = '$_.{0}' -f $ParamName

                        if ($Object -isnot [guid]) {
                            # If it's a string, the filter scriptblock will need to call Get-AdObjectAceGuid
                            $LeftSide += ' -and ((Get-ADObjectAceGuid -Guid $_.{0} -ErrorAction SilentlyContinue) | select -exp Name)' -f $ParamName
                            $ObjectAceTypeParamName = "Name"  # Used for looking up unique types below
                        }
                        else {
                            $ObjectAceTypeParamName = "Guid"  # Used for looking up unique types below
                        }

                        # Build the right side of the comparison (only different if $Specific is specified)
                        $RightSide = $Object.ToString() | ModifySearchRegex
                        if ($Specific) {
                            $RightSide = "^$RightSide`$"
                        }

                        $FilterString = '{0} -match "{1}"' -f $LeftSide, $RightSide

                        # If -Specific was provided, we're done here. If not, there are a few other things to check
                        if ($Specific) {
                            $CurrentFilter += $FilterString
                            break
                        }

                        if ($ParamName -eq "ObjectAceType") {
                            # An ACE doesn't have to have an ObjectAceType to allow permission over the object type for that GUID. For example, an ACE giving
                            # Administrators the 'ExtendedRight' access w/o specifying an ObjectAceType would give Administrators ALL extended rights. This
                            # extra -or for the $FilterString attempts to take care of that
                            $ParamHashTable = @{ 
                                $ObjectAceTypeParamName = $Object | ModifySearchRegex
                                ErrorAction = "SilentlyContinue"
                            }
                            $ExtraFilterStrings = Get-ADObjectAceGuid @ParamHashTable | Select-Object -Unique -ExpandProperty Type | Where-Object { $_ } | ForEach-Object {
                                switch -wildcard ($_) {
                                    ValidatedWrite {
                                        $LimitingAccess = "Self"
                                        break
                                    }

                                    Property* {
                                        $LimitingAccess = "ReadProperty, WriteProperty"
                                        break
                                    }

                                    ClassObject {
                                        $LimitingAccess = "CreateChild, DeleteChild"
                                        break
                                    }

                                    default {
                                        # If it makes it here, the object type matches the right's name
                                        $LimitingAccess = $_
                                    }
                                }

                                '($_.AccessMask -band {0})' -f ([PowerShellAccessControl.ActiveDirectoryRights] $LimitingAccess).value__
                            }

                            if ($ExtraFilterStrings) {
                                $ExtraFilterString = '(-not ($_.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::ObjectAceTypePresent) -and ({0}))' -f ($ExtraFilterStrings -join " -or ")
                                $FilterString = "({0}) -or ({1})" -f $FilterString, $ExtraFilterString
                            }
                        }
                        elseif ($ParamName -eq "InheritedObjectAceType") {
                            $FilterString = "({0}) -or ({1})" -f $FilterString, '(-not ($_.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent))'
                        }

                        $CurrentFilter += $FilterString
                        break
                    }

                    "(Not)?Inherited" {
                        if ($ParamName -eq "NotInherited") {
                            # Negate the $Object value
                            $Object = (-not $Object) -as [switch]
                        }

                        $ParamName = "IsInherited"
                    }

                    "Audit(Success|Failure)" {
                        $Object = [System.Security.AccessControl.AuditFlags]::($ParamName -replace "Audit")
                        $ParamName = "AuditFlags"
                    }

                    "Rights$" {
                        # Lots of different names for the AccessMask. Treat any of the parameters that end
                        # in 'Rights' as an access mask
                        $ParamName = "AccessMask"
                    }

                    .* {
                        # Match on anything. Some parameters will have met a condition and broken out. Others
                        # may have hit, but it was just to massage the ParamName or the data. Finish their
                        # filter building here:

                        $Type = $Object.GetType()
                        if (($Type.IsEnum -and ($Type.GetCustomAttributes([System.FlagsAttribute], $false))) -or $ParamName -eq "AccessMask") {
                            # AccessMask can be numeric, so treat that the same as a flags enumeration:

                            if ($Specific) {
                                # Enumerations must match exactly what was input. 
                                $CurrentFilter += '($_.{0} -eq {1})' -f $ParamName, ([int] $Object)
                            }
                            else { 
                                # Not specific, so a setting that gives more access/rights than what is
                                # being requested can also be returned (so Modify file rights will match
                                # on FullControl as well as Modify)
                                $CurrentFilter += '($_.{0} -band {1}) -eq {1}' -f $ParamName, ([int] $Object)
                            }
                        }
                        elseif ($Type -eq [switch]) {
                            # Any switches (remember -AuditSuccess and -AuditFailure won't make it here)
                            # get a simple filter added:
                            $CurrentFilter += '$_.{0} -eq ${1}' -f $ParamName, $Object.IsPresent
                        }
                        else {
                            # Treat any other types as a string (allow wildcards)
                            $CurrentFilter += '$_.{0} -match "^{1}$"' -f $ParamName, ($Object.ToString() | ModifySearchRegex)
                        }
                    }
                }
            }

            if ($CurrentFilter.Count -gt $__MaxFilterConditionCount) {
                # I've seen PS crash when this is too big (I ran it with 'Get-AccessControlEntry -ObjectAceType (Get-ADObjectAceGuid -Name * -TypesToSearch Property)',
                # which is an insane amount of conditions since the -ObjectAceType just isn't built for that type of filter
                Write-Warning "The condition filter count for the '$ParamName' parameter ($($CurrentFilter.Count)) is greater than the maximum count of $__MaxFilterConditionCount. The '$ParamName' parameter is being ignored."
                $CurrentFilter = @()
            }

            if ($CurrentFilter.Count -gt 0) {
                $Filter += "({0})" -f ($CurrentFilter -join ") -or (")
            }
        }
        #endregion 

        # No conditions, so create a script block that will always return true:
        if ($Filter.Count -eq 0) { $Filter += '$true' }

        try {
            $FilterSB = [scriptblock]::Create("({0})" -f ($Filter -join ") -and ("))
        }
        catch {
            Write-Error $_
            continue
        }
        Write-Debug "$($PSCmdlet.MyInvocation.MyCommand): Filtering SB: $FilterSB"
    }
    process {
        # Go through each SD object:
        foreach ($CurrentObject in $InputObject) {

            if ($CurrentObject.pstypenames -notcontains $__AdaptedSecurityDescriptorTypeName) {
                # If this isn't a Get-Sd or Get-Acl object, try to run Get-SecurityDescriptor on it
                $AuditPropertyExists = [bool] $CurrentObject.Audit

                try {
                    # Call with -Audit switch if the object has an audit property that contains stuff or if the
                    # function itself was called with -Audit
                    $null = $PSBoundParameters.Remove("InputObject")

                    # Didn't come from Get-SecurityDescriptor, so see if Get-SecurityDescriptor can handle it
                    $CurrentObject | Get-SecurityDescriptor -Audit:($AuditPropertyExists -or $Audit) | Get-AccessControlEntry @PSBoundParameters
                }
                catch {
                    Write-Error $_
                }
                continue
            }

            # Build a script block 
            $ScriptBlockString = '$CurrentObject | New-AdaptedAcl @AdaptedAclParams'
            if ($__ObjectsToMergeAces -contains $CurrentObject.ObjectType) {
                $ScriptBlockString += " | MergeAclEntries"
            }

            & ([scriptblock]::Create($ScriptBlockString)) | Where-Object $FilterSB
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function New-AdaptedSecurityDescriptor {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="BySddl")]
        [string] $Sddl,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="ByBinaryForm")]
        [byte[]] $BinarySD,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({$_.BaseType.FullName -eq "System.Enum"})]
        [type] $AccessMaskEnumeration,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [ValidateScript({
            ("System.Management.Automation.ScriptBlock","System.String") -contains $_.GetType().FullName
        })]
        [Alias("Description")]
        [string] $Path = "[NO PATH PROVIDED]",
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType = "Unknown",
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $SdPath = $Path, # Kept as an object so that HandleRefs can come through
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [string] $DisplayName = $Path,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [Alias("PsIsContainer")]
        [switch] $IsContainer = $false,
        [switch] $IsDsObject = $false,
        # This can probably simply replace IsDsObject switch. If this is present, then the
        # object must be a DsObject...
        [string] $DsObjectClass
    )

    process {

        try {
            switch ($PSCmdlet.ParameterSetName) {
                "BySddl" {
                    $SecurityDescriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor($IsContainer, $IsDsObject, $Sddl)
                }

                "ByBinaryForm" {
                    $SecurityDescriptor = New-Object System.Security.AccessControl.CommonSecurityDescriptor($IsContainer, $IsDsObject, $BinarySD, 0)
                }

                default {
                    # Shouldn't get here...
                    throw "Unknown parameter set"
                }
            }
        }
        catch {
            Write-Error $_
            return
        }

        # "Adapt" the object to look more like something we would get with Get-Acl by adding some custom properties:
        # This stuff belongs in a type file (for PS extended type system) (better) or a C# class (best), but using
        # type file, the scripts run don't have access to helper functions, and I haven't gotten around to trying to
        # create a C# class for the 'Adapted' security descriptor
        $AdaptedSdProperites = @{
            Path = $Path
            SdPath = $SdPath
            DisplayName = $DisplayName
            ObjectType = $ObjectType
            SecurityDescriptor = $SecurityDescriptor
        }
        if ($PSBoundParameters.ContainsKey("DsObjectClass")) {
            $AdaptedSdProperites.DsObjectClass = $DsObjectClass
        }

        # This next section is to work around this issue: https://connect.microsoft.com/PowerShell/feedback/details/1045858/add-member-cmdlet-invokes-scriptproperty-members-when-adding-new-member
        $ReturnObject = New-Object object
        foreach ($PropertyEnum in $AdaptedSdProperites.GetEnumerator()) {
            $ReturnObject | Add-Member -MemberType NoteProperty -Name $PropertyEnum.Key -Value $PropertyEnum.Value
        }

        $ReturnObject | Add-Member -MemberType ScriptProperty -Name InheritanceString -Value {
            $Output = @()
            if ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) {
                $Output += "DACL Inheritance: $(if ($this.AreAccessRulesProtected) { "Dis" } else { "En" })abled"
            }

            if ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent) {
                $Output += "SACL Inheritance: $(if ($this.AreAuditRulesProtected) { "Dis" } else { "En" })abled"
            }
            $Output -join "`n"
        } 
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AccessPresent -Value {
            $this.SecurityDescriptor.ControlFlags -match "DiscretionaryAcl"
        } 
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Access -Value {
            $this | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Owner -Value {
            $this | GetPrincipalString -IdentityReference $this.SecurityDescriptor.Owner
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Group -Value {
            $this | GetPrincipalString -IdentityReference $this.SecurityDescriptor.Group
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AccessToString -Value {
            $this | Get-AccessControlEntry -AceType AccessAllowed, AccessDenied | Convert-AclToString -DefaultAppliesTo (GetDefaultAppliesTo -IsContainer:$this.SecurityDescriptor.IsContainer -AccessMaskEnumeration $this.GetAccessMaskEnumeration())
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AuditPresent -Value {
            $this.SecurityDescriptor.ControlFlags -match "SystemAcl"
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Audit -Value {
            $this | Get-AccessControlEntry -AceType SystemAudit
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AuditToString -Value {
            $this | Get-AccessControlEntry -AceType SystemAudit | Convert-AclToString -DefaultAppliesTo (GetDefaultAppliesTo -IsContainer:$this.SecurityDescriptor.IsContainer -AccessMaskEnumeration $this.GetAccessMaskEnumeration())
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAccessRule -Value { 
            param(
                $Rule
            )

            if (-not ($this.AccessPresent)) {
                # DACL doesn't exist, so can't remove anything
                return $false
            }

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName RemoveAccess -Rule $Rule -ErrorAction Stop
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAccessRuleSpecific -Value { 
            param(
                $Rule
            )

            if (-not ($this.AccessPresent)) {
                # DACL doesn't exist, so can't remove anything
                return $false
            }

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName RemoveAccessSpecific -Rule $Rule
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAuditRuleSpecific -Value { 
            param(
                $Rule
            )

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName RemoveAuditSpecific -Rule $Rule

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name RemoveAuditRule -Value { 
            param(
                $Rule
            )

            InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName RemoveAudit -Rule $Rule

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name AddAccessRule -Value {
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
                # DACL doesn't exist, so create an empty one.
                $NewAclCreated = $true
                $this.SecurityDescriptor.DiscretionaryAcl = New-Object System.Security.AccessControl.DiscretionaryAcl (
                    $this.SecurityDescriptor.IsContainer, 
                    $this.SecurityDescriptor.IsDS, 
                    0
                )
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName AddAccess -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    # ACL didn't exist, and there was an error adding the ACE. Set things back to how they were:
                    $this.SecurityDescriptor.DiscretionaryAcl = $null
                }
                throw $_
            }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name AddAuditRule -Value {
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent)) {
                # SACL doesn't exist, so create an empty one.
                $NewAclCreated = $true
                $this.SecurityDescriptor.SystemAcl = New-Object System.Security.AccessControl.SystemAcl ($this.SecurityDescriptor.IsContainer, $this.SecurityDescriptor.IsDS, 0)
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName AddAudit -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    # ACL didn't exist, and there was an error adding the ACE. Set things back to how they were:
                    $this.SecurityDescriptor.SystemAcl = $null
                }
                throw $_
            }

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAccessRule -Value {
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent)) {
                # DACL doesn't exist, so create an empty one.
                $NewAclCreated = $true
                $this.SecurityDescriptor.DiscretionaryAcl = New-Object System.Security.AccessControl.DiscretionaryAcl (
                    $this.SecurityDescriptor.IsContainer, 
                    $this.SecurityDescriptor.IsDS, 
                    0
                )
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.DiscretionaryAcl -MethodName SetAccess -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    # ACL didn't exist, and there was an error adding the ACE. Set things back to how they were:
                    $this.SecurityDescriptor.DiscretionaryAcl = $null
                }
                throw $_
            }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAuditRule -Value {
            param(
                $Rule
            )

            if (-not ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent)) {
                # SACL doesn't exist, so create an empty one.
                $NewAclCreated = $true
                $this.SecurityDescriptor.SystemAcl = New-Object System.Security.AccessControl.SystemAcl ($this.SecurityDescriptor.IsContainer, $this.SecurityDescriptor.IsDS, 0)
            }

            try {
                InvokeCommonAclMethod -Acl $this.SecurityDescriptor.SystemAcl -MethodName SetAudit -Rule $Rule -ErrorAction Stop
            }
            catch {
                if ($NewAclCreated) {
                    # ACL didn't exist, and there was an error adding the ACE. Set things back to how they were:
                    $this.SecurityDescriptor.SystemAcl = $null
                }
                throw $_
            }

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAccessRuleProtection -Value {
            param(
                [bool] $IsProtected, 
                [bool] $PreserveInheritance
            )

            $this.SecurityDescriptor.SetDiscretionaryAclProtection($IsProtected, $PreserveInheritance)

            # Add an extra property that flags this security descriptor as dirty (and needing to be
            # set and re-read)
            $DaclProtectionDirtyString = @()
            $PreserveInheritanceString = $null
            if ($IsProtected) { 
                $DaclProtectionDirtyString += "Disable" 
                if ($PreserveInheritance) {
                    $PreserveInheritanceString = "(Preserve existing ACEs)"
                }
                else {
                    $PreserveInheritanceString = "(Remove existing ACEs)"
                }
            }
            else { $DaclProtectionDirtyString += "Enable" }

            $DaclProtectionDirtyString += "DACL inheritance"

            if ($PreserveInheritanceString) {
                $DaclProtectionDirtyString += $PreserveInheritanceString
            }
            $this | Add-Member -MemberType NoteProperty -Name DaclProtectionDirty -Value ($DaclProtectionDirtyString -join " ") -Force
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetAuditRuleProtection -Value {
            param(
                [bool] $IsProtected,
                [bool] $PreserveInheritance
            )

            $this.SecurityDescriptor.SetSystemAclProtection($IsProtected, $PreserveInheritance)
        
            # Add an extra property that flags this security descriptor as dirty (and needing to be
            # set and re-read)
            $ProtectionDirtyString = @()
            $PreserveInheritanceString = $null
            if ($IsProtected) { 
                $ProtectionDirtyString += "Disable" 
                if ($PreserveInheritance) {
                    $PreserveInheritanceString = "(Preserve existing ACEs)"
                }
                else {
                    $PreserveInheritanceString = "(Remove existing ACEs)"
                }
            }
            else { $ProtectionDirtyString += "Enable" }

            $ProtectionDirtyString += "SACL inheritance"

            if ($PreserveInheritanceString) {
                $ProtectionDirtyString += $PreserveInheritanceString
            }
            $this | Add-Member -MemberType NoteProperty -Name SaclProtectionDirty -Value ($ProtectionDirtyString -join " ") -Force
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name PurgeAccessRules -Value {
            param($Identity)

            if ($this.SecurityDescriptor.DiscretionaryAcl -eq $null) {
                return
            }

            try {
                $Sid = $Identity | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.DiscretionaryAcl.Purge($Sid)

        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name PurgeAuditRules -Value {
            param($Identity)

            if ($this.SecurityDescriptor.SystemAcl -eq $null) {
                return
            }

            try {
                $Sid = $Identity | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.SystemAcl.Purge($Sid)

        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAccessRulesProtected -Value {
            if ($this.GetAccessControlSections() -band [System.Security.AccessControl.AccessControlSections]::Access) {
                [bool] ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected)
            }
            # $null returned if section isn't present. I originally had a warning being output, but that was confusing when doing the format-list view
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAuditRulesProtected -Value {
            if ($this.GetAccessControlSections() -band [System.Security.AccessControl.AccessControlSections]::Audit) {
                [bool] ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclProtected)
            }
            # $null returned if section isn't present. I originally had a warning being output, but that was confusing when doing the format-list view
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAccessRulesCanonical -Value {
            $this.SecurityDescriptor.DiscretionaryAcl.IsCanonical
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name AreAuditRulesCanonical -Value {
            $this.SecurityDescriptor.SystemAcl.IsCanonical
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name SetOwner -Value {
            param(
                $Owner
            )

            try {
                $Sid = $Owner | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
            }
            catch {
                throw $_
            }

            $this.SecurityDescriptor.Owner = $Sid

        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name Sddl -Value {
            $this.SecurityDescriptor.GetSddlForm([System.Security.AccessControl.AccessControlSections]::All)
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetSecurityDescriptorBinaryForm -Value {
            $BinarySD = New-Object byte[] $this.SecurityDescriptor.BinaryLength
            $this.SecurityDescriptor.GetBinaryForm($BinarySD, 0)

            $BinarySD
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAccessControlSections -Value {
            # This is used by some of the DSC resources to be able to tell which sections of an SD
            # are implemented when an SDDL string is being used

            $SectionsContained = [System.Security.AccessControl.AccessControlSections]::None

            foreach ($Section in "Owner", "Group") {
                if ($this.SecurityDescriptor.$Section -ne $null) {
                    $SectionsContained = $SectionsContained -bor [System.Security.AccessControl.AccessControlSections]::$Section
                }
            }

            if ($this.SecurityDescriptor.GetSddlForm("Access") -ne "") {
                # If an SD is provide w/o a DACL section, CommonSecurityDescriptor class creates on w/ an entry that gives everyone full control access. GetSddlForm("Access") will still show
                # a blank section, though.
                $SectionsContained = $SectionsContained -bor [System.Security.AccessControl.AccessControlSections]::Access
            }

            if ($this.SecurityDescriptor.ControlFlags -band [System.Security.AccessControl.ControlFlags] "SystemAclPresent, SystemAclProtected, SystemAclAutoInherited" ) {
                $SectionsContained = $SectionsContained -bor [System.Security.AccessControl.AccessControlSections]::Audit
            }

            [System.Security.AccessControl.AccessControlSections] $SectionsContained

        }
        $ReturnObject | Add-Member -MemberType NoteProperty -Name OriginalOwner -Value $SecurityDescriptor.Owner
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name HasOwnerChanged -Value {
                -not ($this.OriginalOwner -eq $this.SecurityDescriptor.Owner)
        }
        $ReturnObject | Add-Member -MemberType NoteProperty -Name OriginalGroup -Value $SecurityDescriptor.Group
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name HasGroupChanged -Value {
                -not ($this.OriginalGroup -eq $this.SecurityDescriptor.Group)
        }
        $ReturnObject | Add-Member -MemberType ScriptProperty -Name MandatoryIntegrityLabel -Value {
            Get-MandatoryIntegrityLabel -Path $this.SdPath -ObjectType $this.ObjectType | 
                Add-Member -MemberType ScriptMethod -Name ToString -Force -Value { "{0} ({1})" -f $this.Principal, $this.AccessMaskDisplay }
        }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAceCsv -Value {
            param(
                [char] $Delimiter = ","
            )

            $CsvProperties = @(
                "DisplayName"
                "Path"
                "AceType"
                "Principal" 
                @{Name="AccessMask"; Expression={ $_.AccessMaskDisplay }}
                "InheritedFrom"
                "AppliesTo"
                "OnlyApplyToThisContainer"
                "InheritanceString"
                "AuditFlags"
            )

            $this | Get-AccessControlEntry | Select-Object $CsvProperties | ConvertTo-Csv -NoTypeInformation -Delimiter $Delimiter
        }

        # Access ScriptProperty needs access to the access mask enumeration (if one was provided). I originally
        # attached it as a property, but that displays an extra, unnecessary property, so I decided to make it 
        # available via a ScriptMethod:
        if ($PSBoundParameters.ContainsKey("AccessMaskEnumeration")) { $SB = { $AccessMaskEnumeration }.GetNewClosure() }
        else { $SB = {} }
        $ReturnObject | Add-Member -MemberType ScriptMethod -Name GetAccessMaskEnumeration -Value $SB

        $ReturnObject.pstypenames.Insert(0, $__AdaptedSecurityDescriptorTypeName)

        if ($ReturnObject.AreAccessRulesCanonical -eq $false) {
            Write-Warning ("The access rules for '{0}' are not in canonical order. To fix this, please run the 'Repair-AclCanonicalOrder' function." -f $ReturnObject.DisplayName)
        }
        if ($ReturnObject.AreAuditRulesCanonical -eq $false) {
            # I'm not sure how a SACL wouldn't have canonical ordering
        }

        $ReturnObject
    }
}

function Set-Win32SecurityDescriptor {
<#
Right now, this is really just a helper function to allow WMI namespace security to be modified. For that
reason, the module doesn't export it. It can be polished some more and become an exported function.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        # The WMI object/CIM instance to get the security descriptor from
        $InputObject,
        [Parameter(Mandatory=$true)]
        $Win32SecurityDescriptor
    )

    process {
        switch ($InputObject.GetType().FullName) {
            "Microsoft.Management.Infrastructure.CimInstance" {
                # Cim instance, so use Invoke-CimMethod:
                $InvokeMethodCmdlet = "Invoke-CimMethod"
                $MethodNameParamName = "MethodName"
                $ClassNameParamName = "ClassName"
                $ArgumentsParamName = "Arguments"
                $Arguments = @{ Descriptor = $Win32SecurityDescriptor }
            }
            "System.Management.ManagementObject" {
                # Old gwmi object, so use Invoke-WmiMethod:
                $InvokeMethodCmdlet = "Invoke-WmiMethod"
                $MethodNameParamName = "Name"
                $ClassNameParamName = "Class"
                $ArgumentsParamName = "ArgumentList"
                $Arguments = $Win32SecurityDescriptor

            }
            default {
                throw "Unknown object type passed to `$InputObject: $_"
            }
        }

        # Parameters that will be passed to the Invoke-(WMI|Cim)Method cmdlet
        $InvokeMethodParams = @{
            ErrorAction = "Stop"
            $ArgumentsParamName = $Arguments
            $MethodNameParamName = "SetSecurityDescriptor"
        }

        try {
            $Results = $InputObject | & $InvokeMethodCmdlet @InvokeMethodParams
            CheckExitCode $Results.ReturnValue -Action "Setting Win32 security descriptor"
        }
        catch {
            Write-Error ("Error invoking the WMI method '{0}' on the input object '{2}': {1}" -f $InvokeMethodParams.$MethodNameParamName, $_.Exception.Message, $WmiPath) -ErrorId $_.Exception.HResult
            return
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-Win32SecurityDescriptor {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $InputObject,
        [switch] $Sddl,
        [switch] $BinarySD,
        [switch] $SddlOld,
        [switch] $BinarySDOld
    )

    process {

        switch ($InputObject.GetType().FullName) {
            "Microsoft.Management.Infrastructure.CimInstance" {
                # Cim instance, so use Invoke-CimMethod:
                $InvokeMethodCmdlet = "Invoke-CimMethod"
                $MethodNameParamName = "MethodName"
                $ClassNameParamName = "ClassName"

                # We want to attach a path to the object that is returned. That information
                # will be very useful if multiple objects are fed into the function at one
                # time. Unfortunately, it seems that CimInstance objects don't have a path
                # string already made. B/c of this, I'm attempting to create my own
                $WmiPath = $InputObject | Get-CimPathFromInstance
                $WmiClass = $InputObject.CimClass.CimClassName
            }
            "System.Management.ManagementObject" {
                # Old gwmi object, so use Invoke-WmiMethod:
                $InvokeMethodCmdlet = "Invoke-WmiMethod"
                $MethodNameParamName = "Name"
                $ClassNameParamName = "Class"

                # See how much easier this is than the CimInstance?
                $WmiPath = $InputObject.__PATH
                $WmiClass = $InputObject.__CLASS
            }
            default {
                Write-Error "Unknown object type passed to `$InputObject: $_"
                return
            }
        }

        # Parameters that will be passed to the Invoke-(WMI|Cim)Method cmdlet
        $InvokeMethodParams = @{
            WhatIf = $false
            Confirm = $false
            ErrorAction = "Stop"
            $MethodNameParamName = "GetSecurityDescriptor"
        }

        try {
            $Results = $InputObject | & $InvokeMethodCmdlet @InvokeMethodParams
        }
        catch {
            Write-Error ("Error invoking the WMI method '{0}' on the input object '{2}': {1}" -f $InvokeMethodParams.$MethodNameParamName, $_.Exception.Message, $WmiPath) -ErrorId $_.Exception.HResult
            return
        }

        try {
            $Results.ReturnValue | CheckExitCode -Action ("Invoking WMI method '{0}'" -f $InvokeMethodParams.$MethodNameParamName) -ErrorAction Stop
        }
        catch {
            Write-Error $_.Exception.Message
            return
        }

        $ReturnObjectProperties = @{ 
            Path = $WmiPath
            Class = $WmiClass
            InputObject = $InputObject
        }

        $InvokeMethodParams.$ClassNameParamName = "Win32_SecurityDescriptorHelper"

        #Arguments/ArgumentList Parameters are very different for the two cmdlets:
        switch ($InvokeMethodCmdlet) {
            "Invoke-CimMethod" {
                $InvokeMethodParams.Arguments = @{ Descriptor = $Results.Descriptor }
            }
            "Invoke-WmiMethod" {
                $InvokeMethodParams.ArgumentList = @($Results.Descriptor)
            }
            default {
                throw "How in the world did you get this far into the function??"
            }
        }

        # Add the Win32SD to the return object:
        $ReturnObjectProperties.Add("Win32SD", $Results.Descriptor)

        if ($PSBoundParameters.ContainsKey("SDDL") -or $PSBoundParameters.ContainsKey("BinarySD")) {
            # Because of bug in Win32_SecurityDescriptorHelper class' conversion of Win32SD to SDDL
            # and/or binary, we're going to manually do conversion by building the SD from scratch

            $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor(
                $Results.Descriptor.ControlFlags,
                $Results.Descriptor.Owner.SIDString,
                $Results.Descriptor.Group.SIDString,
                (New-Object System.Security.AccessControl.RawAcl (0,0)),  # Blank SACL
                (New-Object System.Security.AccessControl.RawAcl (0,0))   # Blank DACL
            )
            
            # Add discretionary DACL:
            $Results.Descriptor.DACL | ConvertToCommonAce -KeepInheritedFlag | ForEach-Object {
                $RawSD.DiscretionaryAcl.InsertAce($RawSD.DiscretionaryAcl.Count, $_)
            }

            # Add system ACEs to SACL
            $Results.Descriptor.SACL | ConvertToCommonAce -KeepInheritedFlag | ForEach-Object {
                $RawSD.SystemAcl.InsertAce($RawSD.SystemAcl.Count, $_)
            }

            if ($PSBoundParameters.ContainsKey("SDDL")) {
                $ReturnObjectProperties.Add("SDDL", $RawSD.GetSddlForm("All"))
            }

            if ($PSBoundParameters.ContainsKey("BinarySD")) {
                $BinarySdBytes = New-Object byte[] $RawSD.BinaryLength
                $RawSD.GetBinaryForm($BinarySdBytes, 0)
                $ReturnObjectProperties.Add("BinarySD", $BinarySdBytes)
            }
        }
        
        # Original creation of SDDL and/or BinarySD:
        
        # Function can return the Win32SD in SDDL or Binary form
        # NOTE: There is a bug in the helper functions that prevents inheritance from being
        #       properly represented. (see Notes section in the help for this function)
        "SDDL","BinarySD" | ForEach-Object {
            if ($PSBoundParameters["$($_)Old"]) {
                $InvokeMethodParams.$MethodNameParamName = "Win32SDTo$_"
            
                try {
                    $ConvertResults = & $InvokeMethodCmdlet @InvokeMethodParams
                }
                catch {
                    throw ("Error invoking the WMI method '{0}' on the input object: {1}" -f $InvokeMethodParams.$MethodNameParamName, $_.Exception.Message)
                }

                if ($ConvertResults.ReturnValue -ne 0) {
                    Write-Error ("Error converting Win32_SecurityDescriptor to $_; return code from WMI method = {0}" -f $ConvertResults.ReturnValue)
                    $FinalResults = "[ERROR]"
                }
                else {
                    $FinalResults = $ConvertResults.$_
                }

                $ReturnObjectProperties.Add("$($_)Old", $FinalResults)

            }
        }

        $ReturnObject = New-Object PSObject -Property $ReturnObjectProperties

        $ReturnObject  # Output object
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function ConvertTo-Win32SecurityDescriptor {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="Sddl")]
        # SDDL representation of a security descriptor
        [string] $Sddl,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName="BinarySD")]
        # Binary representation of a security descriptor
        [byte[]] $BinarySD,
        # Return just the Win32_SecurityDescriptor (by default, an object that contains both the original input
        # and the Win32_SecurityDescriptor object are returned
        [switch] $ValueOnly,
        # Return a System.ManagementObject istance of the Win32SD instead of a CimInstance.
        [switch] $LegacyWmiObject
    )

    process {

        if ($PSVersionTable.PSVersion -lt "3.0") {
            $LegacyWmiObject = $true
        }

        $InputSD = (Get-Variable -Name ($PSCmdlet.ParameterSetName) -ValueOnly)

        <#
            The quicker way to do this is to just use Class, Name, and Argument
            as the parameter names. Class and Name params are aliased for the Cim
            cmdlets, and Argument is enough to work for both cmdlets, but I decided
            to use the full param names in the hash table.
        #>
        if ($LegacyWmiObject) {
            if ($PSCmdlet.ParameterSetName -eq "BinarySD") {
                $InputSD = [byte[]] $InputSD
            }

            # ManagementObject
            $MethodName = "Invoke-WmiMethod"
            $ClassNameParam = "Class"
            $MethodNameParam = "Name"
            $ArgumentsParam = "ArgumentList"
            $ArgumentsValue = ,$InputSD
        }
        else {
            # CimInstance param names:
            $MethodName = "Invoke-CimMethod"
            $ClassNameParam = "ClassName"
            $MethodNameParam = "MethodName"
            $ArgumentsParam = "Arguments"
            $ArgumentsValue = @{
                $PSCmdlet.ParameterSetName = $InputSD
            }
        }
        
        $InvokeMethodParams = @{
            $ClassNameParam = "Win32_SecurityDescriptorHelper"
            ErrorAction = "Stop"
            $MethodNameParam = "{0}ToWin32SD" -f $PSCmdlet.ParameterSetName
            $ArgumentsParam = $ArgumentsValue
        }

        try {
            $Results = & $MethodName @InvokeMethodParams
        }
        catch {
            Write-Error ("Error invoking the WMI method '{0}' on the input object: {1}" -f $InvokeMethodParams.$MethodName, $_.Exception.Message)
            return
        }

        try {
            CheckExitCode -ExitCode $Results.ReturnValue -Action "Converting security descriptor into Win32_SecurityDescriptor" -ErrorAction Stop
        }
        catch {
            Write-Error $_
            return
        }

        $ReturnObject = New-Object PSObject -Property @{
            $PSCmdlet.ParameterSetName = $InputSD
            Descriptor = $Results.Descriptor
        }

        if ($ValueOnly) {
            $ReturnObject | Select-Object -ExpandProperty Descriptor
        }
        else {
            $ReturnObject
        }
    }
}

function ConvertFrom-Win32SecurityDescriptor {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $InputObject,
        [switch] $Sddl,
        [switch] $BinarySD,
        [switch] $SddlOld,
        [switch] $BinarySDOld
    )

    begin {
        if (-not ($PSBoundParameters.Keys | where { $_ -ne "InputObject" })) {
            # No swiches provided, so return Sddl and BinarySd forms by default
            $null = $PSBoundParameters.Add("Sddl", $true)
            $null = $PSBoundParameters.Add("BinarySD", $true)
        }
    }

    process {
        # Create common variables to store the differences b/w the different input object types:
        switch ($InputObject.GetType().FullName) {
            "Microsoft.Management.Infrastructure.CimInstance" {
                # Cim instance, so use Invoke-CimMethod:
                $InvokeMethodCmdlet = "Invoke-CimMethod"
                $MethodNameParamName = "MethodName"
                $ClassNameParamName = "ClassName"

                # We want to attach a path to the object that is returned. That information
                # will be very useful if multiple objects are fed into the function at one
                # time. Unfortunately, it seems that CimInstance objects don't have a path
                # string already made. B/c of this, I'm attempting to create my own
                $WmiPath = $InputObject | Get-CimPathFromInstance
                $WmiClass = $InputObject.CimClass.CimClassName
            }
            "System.Management.ManagementBaseObject" {
                # Old gwmi object, so use Invoke-WmiMethod:
                $InvokeMethodCmdlet = "Invoke-WmiMethod"
                $MethodNameParamName = "Name"
                $ClassNameParamName = "Class"

                # See how much easier this is than the CimInstance?
                $WmiPath = $InputObject.__PATH
                $WmiClass = $InputObject.__CLASS
            }
            default {
                Write-Error "Unknown object type passed to `$InputObject: $_"
                return
            }
        }

        if ("__SecurityDescriptor", "Win32_SecurityDescriptor" -notcontains $WmiClass) {
            Write-Error "`$InputObject must be an instance of the Win32_SecurityDescriptor class. Instead, it is an instance of '$WmiClass'"
            return
        }

        $ReturnObjectProperties = @{

        }

        if ($PSBoundParameters.ContainsKey("SDDL") -or $PSBoundParameters.ContainsKey("BinarySD")) {
            # Because of bug in Win32_SecurityDescriptorHelper class' conversion of Win32SD to SDDL
            # and/or binary, we're going to manually do conversion by building the SD from scratch

            $RawSD = New-Object System.Security.AccessControl.RawSecurityDescriptor(
                $InputObject.ControlFlags,
                $InputObject.Owner.SIDString,
                $InputObject.Group.SIDString,
                (New-Object System.Security.AccessControl.RawAcl (0,0)),  # Blank SACL
                (New-Object System.Security.AccessControl.RawAcl (0,0))   # Blank DACL
            )
            
            # Add discretionary DACL:
            $InputObject.DACL | ConvertToCommonAce -KeepInheritedFlag | ForEach-Object {
                $RawSD.DiscretionaryAcl.InsertAce($RawSD.DiscretionaryAcl.Count, $_)
            }

            # Add system ACEs to SACL
            $InputObject.SACL | ConvertToCommonAce -KeepInheritedFlag | ForEach-Object {
                $RawSD.SystemAcl.InsertAce($RawSD.SystemAcl.Count, $_)
            }

            if ($PSBoundParameters.ContainsKey("SDDL")) {
                $ReturnObjectProperties."SDDL" = $RawSD.GetSddlForm("All")
            }

            if ($PSBoundParameters.ContainsKey("BinarySD")) {
                $BinarySdBytes = New-Object byte[] $RawSD.BinaryLength
                $RawSD.GetBinaryForm($BinarySdBytes, 0)
                $ReturnObjectProperties."BinarySD" = $BinarySdBytes
            }
        }
        
        # Original creation of SDDL and/or BinarySD:
        
        # Function can return the Win32SD in SDDL or Binary form
        # NOTE: There is a bug in the helper functions that prevents inheritance from being
        #       properly represented. (see Notes section in the help for this function)

        $InvokeMethodParams = @{
            $ClassNameParamName = "Win32_SecurityDescriptorHelper"
        }

        switch ($InvokeMethodCmdlet) {
            "Invoke-CimMethod" {
                $InvokeMethodParams.Arguments = @{ Descriptor = $InputObject }
            }
            "Invoke-WmiMethod" {
                $InvokeMethodParams.ArgumentList = @($InputObject)
            }
            default {
                throw "How in the world did you get this far into the function??"
            }
        }

        "SDDL","BinarySD" | ForEach-Object {
            if ($PSBoundParameters["$($_)Old"]) {
                $InvokeMethodParams.$MethodNameParamName = "Win32SDTo$_"
            
                try {
                    $ConvertResults = & $InvokeMethodCmdlet @InvokeMethodParams
                }
                catch {
                    throw ("Error invoking the WMI method '{0}' on the input object: {1}" -f $InvokeMethodParams.$MethodNameParamName, $_.Exception.Message)
                }

                if ($ConvertResults.ReturnValue -ne 0) {
                    Write-Error ("Error converting Win32_SecurityDescriptor to $_; return code from WMI method = {0}" -f $ConvertResults.ReturnValue)
                    $FinalResults = "[ERROR]"
                }
                else {
                    $FinalResults = $ConvertResults.$_
                }

                $ReturnObjectProperties."$($_)Old" = $FinalResults

            }
        }

        New-Object PSObject -Property $ReturnObjectProperties

    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-SecurityDescriptor {

    [CmdletBinding(DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        $InputObject,
        [Parameter(ParameterSetName='DirectPath', Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Parameter(ParameterSetName='DirectPath')]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [switch] $Audit,
        [Parameter(ParameterSetName='DirectPath')]
        [switch] $IsContainer = $false
    )

    process {

        if ($PSCmdlet.ParameterSetName -eq "Path" -and (-not $PSBoundParameters.ContainsKey("Path"))) {
            # GetPathInformation uses PSBoundParameters, so set it up as if the default path was passed
            # as a bound parameter:
            $null = $PSBoundParameters.Add("Path", $Path)
        }

        foreach ($ObjectInfo in (GetPathInformation @PSBoundParameters)) {
            if ($ObjectInfo.Sddl) {
                # If GetPathInformation returned SDDL, that means the InputObject was already a security
                # descriptor object (one of native .NET ones that this module works with: File, Folder, Registry
                # key, or AD object as of v3.0)
                #
                # In that case, don't do anything since this section handles retrieving that information
            }
            elseif ($ObjectInfo.ObjectType -eq $__PowerShellAccessControlResourceTypeName) {
                # We've got to do something special here
                switch ($ObjectInfo.InputObject.GetType().FullName) {
                    { $_ -eq "System.Management.ManagementObject" -or
                      $_ -eq "Microsoft.Management.Infrastructure.CimInstance" } {

                        # This is a WMI object, so attempt to get Win32SD (other properties should
                        # have already been handled
                        try {
                            $Win32SD = $ObjectInfo.InputObject | Get-Win32SecurityDescriptor -Sddl -ErrorAction Stop
                        }
                        catch {
                            # Catching error lets user decide error action
                            Write-Error $_
                            return
                        }

                        $ObjectInfo.Sddl = $Win32SD.Sddl
                    }

                    "Microsoft.WSMan.Management.WSManConfigLeafElement" {
                        $ObjectInfo.Sddl = $ObjectInfo.InputObject.Value
                    }
                }
            }
            else {

                if ($Audit) {
                    $SecurityInfo = [PowerShellAccessControl.PInvoke.SecurityInformation]::All
                }
                else {
                    $SecurityInfo = [PowerShellAccessControl.PInvoke.SecurityInformation] "Owner, Group, Dacl"
                }

                try {
                    $SecInfoParams = @{
                        ObjectType = $ObjectInfo.ObjectType
                    }

                    if ($ObjectInfo.Handle) {
                        $SecInfoParams.Handle = $ObjectInfo.SdPath = $ObjectInfo.Handle
                    }
                    else {
                        $SecInfoParams.Path = $ObjectInfo.SdPath
                    }

                    $BinSD = GetSecurityInfo -SecurityInformation $SecurityInfo -ErrorAction Stop @SecInfoParams
                    $ObjectInfo.BinarySD = $BinSD
                }
                catch {
                    # Catching error and re-writing it makes it so user can decide the error action
                    Write-Error $_
                    continue
                }
            }

            # There are a few properties that may exist in the hashtable that can't be passed to 
            # New-AdaptedSecurityDescriptor. Remove those:
            foreach ($PropToRemove in "Handle", "InputObject") {
                if ($ObjectInfo.$PropToRemove) {
                    $ObjectInfo.Remove($PropToRemove)
                }
            }

            # Now we can splat $ObjectInfo to New-AdaptedSecurityDescriptor
            try {
                New-AdaptedSecurityDescriptor -ErrorAction Stop @ObjectInfo
            }
            catch {
                Write-Error $_
                continue
            }
        } # end foreach()
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Set-SecurityDescriptor {

    [CmdletBinding(DefaultParameterSetName = '__AllParameterSets', SupportsShouldProcess=$true, ConfirmImpact='High')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [ValidateScript({ $_ -isnot [array] })]
        $SDObject,
        [Parameter(Mandatory=$true, ParameterSetName='InputObject')]
        $InputObject,
        [Parameter(Mandatory=$true, ParameterSetName='Path')]
        [string[]] $Path,
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath')]
        [string[]] $LiteralPath,
        [switch] $Force,
        [System.Security.AccessControl.AccessControlSections] $Sections = "Access, Audit"

    )

    process {

        # SDObject must be an "adapted" SD (from this module). If it's a native .NET SD (like from Get-Acl),
        # that's OK, but we must convert it. Thankfully, Get-SD can do that:
        if ($SDObject.GetType().FullName -match "System\.(Security\.AccessControl|DirectoryServices)\.(\w+)Security") {
            $SDObject = $SDObject | Get-SecurityDescriptor -ErrorAction Stop
        }
        elseif ($SDObject.pstypenames -notcontains $__AdaptedSecurityDescriptorTypeName) {
            # Invalid SD Object!
            Write-Error ("Unknown SDObject type: {0}" -f $SDObject.GetType().FullName)
        }

        # If Path, LiteralPath, or InputObject are passed, that means user wants SD from $SDObject
        # put onto the item described by one of those parameters:
        if ($PSCmdlet.ParameterSetName -eq [System.Management.Automation.ParameterAttribute]::AllParameterSets) {
            # The path and object type used for SetSecurityInfo will come straight from the SD
            $ObjectsToSet = @{
                SdPath = $SDObject.SdPath
                ObjectType = $SDObject.ObjectType
            }
        }
        else {
            $ObjectsToSet = GetPathInformation @PSBoundParameters
        }

        # The key to this whole thing is the [SecurityInformation] that is passed to
        # the SetSecurityDescriptor function. We'll build that based on the [ControlFlags]
        # that is attached to the security descriptor object.
        $ControlFlags = $SDObject.SecurityDescriptor.ControlFlags
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation = 0
        $SdParts = @{}  # This will hold the actual SD parts (Owner, Group, DACL, SACL)

        # If $Sections wasn't specified and the owner is different, go ahead and enable it as well.
        if ((-not $PSBoundParameters.ContainsKey("Sections")) -and $SDObject.HasOwnerChanged) {
            $Sections = $Sections -bxor [System.Security.AccessControl.AccessControlSections]::Owner
        }

        # Same as above, except for Group
        if ((-not $PSBoundParameters.ContainsKey("Sections")) -and $SDObject.HasGroupChanged) {
            $Sections = $Sections -bxor [System.Security.AccessControl.AccessControlSections]::Group
        }

        # Check to make sure owner section specified and that owner on SD isn't null
        if ($Sections -band [System.Security.AccessControl.AccessControlSections]::Owner -and $SDObject.SecurityDescriptor.Owner) {
            # Owner should be set
            $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Owner
            $SdParts.Owner = $SDObject.SecurityDescriptor.Owner
        }
        # Do the same thing for group as owner
        if ($Sections -band [System.Security.AccessControl.AccessControlSections]::Group -and $SDObject.SecurityDescriptor.Group) {
            $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Group
            $SdParts.Group = $SDObject.SecurityDescriptor.Group
        }

        if ($Sections -band [System.Security.AccessControl.AccessControlSections]::Access) {
            # Two checks: 
            #   1. Function must have been called with 'Access' as one of the sections (it is by default)
            #   2. The SD control flags must show that the SD actually has a DACL
            if ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) {
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Dacl
            }
            if ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclProtected) {
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedDacl
            }
            elseif ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::DiscretionaryAclPresent) {
                # Not protected, and DACL is present; set UnprotectedDacl flag
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedDacl
            }

            $SdParts.DiscretionaryAcl = $SDObject.SecurityDescriptor.DiscretionaryAcl
        }

        # Do the exact same thing for the SACL
        if ($Sections -band [System.Security.AccessControl.AccessControlSections]::Audit) {
            if ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent) {
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl
            }
            if ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclProtected) {
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedSacl
            }
            elseif ($ControlFlags -band [System.Security.AccessControl.ControlFlags]::SystemAclPresent) {
                # Not protected, and SACL is present; set UnprotectedSacl flag
                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedSacl
            }

            $SdParts.SystemAcl = $SDObject.SecurityDescriptor.SystemAcl
        }

        foreach ($Object in $ObjectsToSet) {

            $SetSdParams = @{
                ObjectType = $Object.ObjectType
                SecurityInfo = $SecurityInformation
            }
            switch ($Object.SdPath.GetType().FullName) {
                { $_ -eq "System.IntPtr" -or $_ -eq "System.Runtime.InteropServices.HandleRef" } {
                    # Handle
                    $SetSdParams.Handle = $Object.SdPath
                }
                "System.String" {
                    # Text path
                    $SetSdParams.Path = $Object.SdPath
                }

                default {
                    Write-Error "Unknown security descriptor path for object with type '$ObjectType'"
                    return
                }
            }

            $ShouldProcessTarget = "{0} ({1})" -f $Object.SdPath, $Object.ObjectType
            $ShouldProcessAction = GetSdString -SDObject $SDObject -SecurityInformation $SecurityInformation

            if ($Force -and (-not $WhatIf)) {
                $ShouldProcessResult = $true
            }
            else {
                $ShouldProcessResult = $PSCmdlet.ShouldProcess($ShouldProcessTarget, $ShouldProcessAction)
            }        

            if ($ShouldProcessResult) {

                if ($Object.ObjectType -eq $__PowerShellAccessControlResourceTypeName) {
                    try {
                        $PathInfo = New-Object PSObject -Property @{
                            Path = $Object.SdPath
                            ObjectType = $__PowerShellAccessControlResourceTypeName
                        } | GetPathInformation

                        # We've got to do something special here
                        switch ($PathInfo.InputObject.GetType().FullName) {
                            { $_ -eq "System.Management.ManagementObject" -or
                              $_ -eq "Microsoft.Management.Infrastructure.CimInstance" } {

                                $UseLegacyWmi = $false
                                if ($_ -eq "System.Management.ManagementObject") { 
                                    $UseLegacyWmi = $true 
                                }

                                # This is a WMI object, so attempt to get Win32SD
                                $Win32SD = ConvertTo-Win32SecurityDescriptor -Sddl $SDObject.Sddl -LegacyWmiObject:$UseLegacyWmi -ErrorAction Stop

                                $PathInfo.InputObject | Set-Win32SecurityDescriptor -Win32SecurityDescriptor $Win32SD.Descriptor    
                                
                            }

                            "Microsoft.WSMan.Management.WSManConfigLeafElement" {
                                Set-Item -Path $SDObject.SdPath -Value $SDObject.Sddl -Force:$Force -ErrorAction Stop
                            }
                        }
                    }
                    catch {
                        # Catching error lets user decide error action
                        Write-Error $_
                        continue
                    }
                }
                else {
                    SetSecurityInfo @SetSdParams @SdParts
                }
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Enable-AclInheritance {
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias("SDObject")]
        $InputObject,
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Alias("DACL","Access")]
        [switch] $DiscretionaryAcl,
        [Alias("SACL","Audit")]
        [switch] $SystemAcl,
        [switch] $Apply,
        [switch] $PassThru,
        [switch] $Force
    )
        
    begin {
        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false
        }

        if (-not $PSBoundParameters.ContainsKey("DiscretionaryAcl") -and
            -not $PSBoundParameters.ContainsKey("SystemAcl")) {
            # Neither Acl was specified. This will actually happen
            # a lot; just set it up like they passed Dacl switch:
            $DiscretionaryAcl = $true
        }

        $ActionTextSecInfo = 0
        if ($DiscretionaryAcl) { $ActionTextSecInfo = $ActionTextSecInfo -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedDacl }
        if ($SystemAcl) { $ActionTextSecInfo = $ActionTextSecInfo -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedSacl }

    }

    process {

        # Determine which methods to call for each SD
        $MethodsToInvoke = @()
        if ($DiscretionaryAcl) { $MethodsToInvoke += "SetAccessRuleProtection" }
        if ($SystemAcl) { $MethodsToInvoke += "SetAuditRuleProtection" }


        if ($PSCmdlet.ParameterSetName -ne "InputObject") {
            # If a path was passed and the -SystemAcl switch was also passed, Get-SD will need
            # to get the SACL:
            if ($SystemAcl) { $Audit = $true }
            else { $Audit = $false }

            $Params = @{
                $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
                Audit = $Audit
            }

            $InputObject = Get-SecurityDescriptor @Params -ErrorAction Stop

            # SD object wasn't passed, so assume user wants immediate results
            # Change the PSBoundParameters b/c loop through InputObject checks that. User
            # shouldn't be able to call function with an InputObject while a path was passed
            # b/c they are different parameter sets
            $PSBoundParameters.Apply = (-not $PassThru) -or $Apply # If -PassThru was specified, don't set apply (unless it was already set)
        }

        foreach ($CurrentSDObject in $InputObject) {
            # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
            # of the loop to prevent unwanted apply actions
            $Apply = $PsBoundParameters.Apply

            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

            $TypeName = $CurrentSDObject.GetType().FullName

            if ($TypeName -eq "System.Security.AccessControl.RegistrySecurity" -or
                $TypeName -match "System.Security.AccessControl.(File|Directory)Security") {

                # The SDObject is a .NET file or registry security object from Get-Acl
                # This is fine, and no extra work should be necessary b/c the methods that
                # will be called are the same for Get-Acl objects and Get-SD objects
            }
            elseif (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName)) {

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                }
                catch {
                    Write-Error $_
                    return
                }

                # If -PassThru was specified, don't set apply (unless it was already set)
                $Apply = (-not $PassThru) -or $Apply 
            }

            foreach ($MethodName in $MethodsToInvoke) {
                if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, "Invoke $MethodName method")) {
                    $CurrentSDObject.$MethodName.Invoke($false, $false) # Second param doesn't matter
                }
            }

            if ($Apply) {
                Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                $Params = @{
                    __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                    __DefaultReturn = [ref] $__DefaultReturn
                    Action = GetSdString -SDObject $CurrentSDObject -SecurityInformation $ActionTextSecInfo
                    Target = $CurrentSDObject.Path
                }
                if (CustomShouldProcess @Params) {
                    Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false
                }
            }
            if ($PassThru) {
                $CurrentSDObject
                Write-Warning ("Please apply the security descriptor for '{0}' and get it again to reflect any inherited entries" -f $CurrentSDObject.Path)
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Disable-AclInheritance {
    
    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias("SDObject")]
        $InputObject,
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Alias("DACL", "Access")]
        [switch] $DiscretionaryAcl,
        [Alias("SACL", "Audit")]
        [switch] $SystemAcl,
        [switch] $Apply,
        [switch] $PassThru,
        [switch] $Force,
        [switch] $PreserveExistingAces
    )
        
    begin {

        # If user doesn't specify which ACL to perform this on, assume they want to do it to the DACL only
        if (-not $PSBoundParameters.ContainsKey("DiscretionaryAcl") -and
            -not $PSBoundParameters.ContainsKey("SystemAcl")) {
            # Neither Acl was specified. This will actually happen
            # a lot; just set it up like they passed Dacl switch:
            $DiscretionaryAcl = $true
        }

        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false

            # Force wasn't provided, so also check to see if $PreserveExistingAces was provided,
            # and if not, prompt user
            if (-not $PSBoundParameters.ContainsKey("PreserveExistingAces")) {
                $AclsToModify = @()
                if ($DiscretionaryAcl) { $AclsToModify += "discretionary ACL" }
                if ($SystemAcl) { $AclsToModify += "system ACL" }

                $PreservePromptText = @"
Warning: If you proceed, inheritable parent permissions will no longer
propagate to the object's {0}.

- Select Add to convert and add inherited parent permissions as explicit
permissions.

- Select Remove to remove inherited parent permissions.

- Select Cancel if you do not want to modify inheritance settings at this time.

To avoid this prompt in the future, please use either the -PreserveExistingAces 
or -Force flags with the {1} command.
"@ -f ($AclsToModify -join " and "), $MyInvocation.MyCommand
                
                switch (echo Add, Remove, Cancel | Select-SingleObject -PromptMode PromptForChoice -Title $PreservePromptText -PromptForChoiceTitle $MyInvocation.MyCommand) {
                    Add {
                        $PreserveExistingAces = $true
                    }

                    Remove {
                        $PreserveExistingAces = $false
                    }

                    default {
                        throw ("Modification of {0} cancelled by user" -f ($AclsToModify -join " and "))
                    }
                }
            }
        }

        $ActionTextSecInfo = 0
        if ($DiscretionaryAcl) { $ActionTextSecInfo = $ActionTextSecInfo -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedDacl }
        if ($SystemAcl) { $ActionTextSecInfo = $ActionTextSecInfo -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedSacl }
    }

    process {

        # Determine which methods to call for each SD
        $MethodsToInvoke = @()

        if ($DiscretionaryAcl) { $MethodsToInvoke += "SetAccessRuleProtection" }
        if ($SystemAcl) { $MethodsToInvoke += "SetAuditRuleProtection" }


        if ($PSCmdlet.ParameterSetName -ne "InputObject") {
            # If a path was passed and the -SystemAcl switch was also passed, Get-SD will need
            # to get the SACL:
            if ($SystemAcl) { $Audit = $true }
            else { $Audit = $false }

            $Params = @{
                $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
                Audit = $Audit
            }
            $InputObject = Get-SecurityDescriptor @Params -ErrorAction Stop

            # SD object wasn't passed, so assume user wants immediate results
            # Change the PSBoundParameters b/c loop through InputObject checks that. User
            # shouldn't be able to call function with an InputObject while a path was passed
            # b/c they are different parameter sets
            $PSBoundParameters.Apply = (-not $PassThru) -or $Apply # If -PassThru was specified, don't set apply (unless it was already set)
        }

        foreach ($CurrentSDObject in $InputObject) {
            # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
            # of the loop to prevent unwanted apply actions
            $Apply = $PsBoundParameters.Apply

            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

            $TypeName = $CurrentSDObject.GetType().FullName
            if ($TypeName -eq "System.Security.AccessControl.RegistrySecurity" -or
                $TypeName -match "System.Security.AccessControl.(File|Directory)Security") {

                # The SDObject is a .NET file or registry security object from Get-Acl
                # This is fine, and no extra work should be necessary b/c the methods that
                # will be called are the same for Get-Acl objects and Get-SD objects
            }
            elseif (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName)) {

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop
                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                }
                catch {
                    Write-Error $_
                    return
                }

                # If -PassThru was specified, don't set apply (unless it was already set)
                $Apply = (-not $PassThru) -or $Apply 
            }

            foreach ($MethodName in $MethodsToInvoke) {
                if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, "Invoke $MethodName method; preserve existing entries: $PreserveExistingAces")) {
                    $CurrentSDObject.$MethodName.Invoke($true, $PreserveExistingAces)
                }
            }

            if ($Apply) {
                Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                $Params = @{
                    __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                    __DefaultReturn = [ref] $__DefaultReturn
                    Action = GetSdString -SDObject $CurrentSDObject -SecurityInformation $ActionTextSecInfo
                    Target = $CurrentSDObject.Path
                }
                if (CustomShouldProcess @Params) {
                    Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false
                }
            }
            if ($PassThru) {
                $CurrentSDObject
                Write-Warning ("Please apply the security descriptor for '{0}' and get it again to reflect any inherited entries" -f $CurrentSDObject.Path)
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Repair-AclCanonicalOrder {

    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias("SDObject")]
        $InputObject,
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Alias("DACL", "Access")]
        [switch] $DiscretionaryAcl,
        [Alias("SACL", "Audit")]
        [switch] $SystemAcl,
        [switch] $Apply,
        [switch] $PassThru,
        [switch] $Force
    )
        
    begin {
        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false
        }
    }

    process {

        if (-not $PSBoundParameters.ContainsKey("DiscretionaryAcl") -and
            -not $PSBoundParameters.ContainsKey("SystemAcl")) {
            # Neither Acl was specified. This will actually happen
            # a lot; just set it up like they passed Dacl switch:
            $DiscretionaryAcl = $true
        }

        # Determine which ACLs will be checked later:
        $PropertyNames = @()
        if ($DiscretionaryAcl) { $PropertyNames += "Access" }
        if ($SystemAcl) { $PropertyNames += "Audit" }

        if ($PSCmdlet.ParameterSetName -ne "InputObject") {
            # If a path was passed and the -SystemAcl switch was also passed, Get-SD will need
            # to get the SACL:
            if ($SystemAcl) { $Audit = $true }
            else { $Audit = $false }

            $Params = @{
                $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
                Audit = $Audit
            }

            $InputObject = Get-SecurityDescriptor @Params -ErrorAction Stop

            # SD object wasn't passed, so assume user wants immediate results
            # Change the PSBoundParameters b/c loop through InputObject checks that. User
            # shouldn't be able to call function with an InputObject while a path was passed
            # b/c they are different parameter sets
            $PSBoundParameters.Apply = (-not $PassThru) -or $Apply # If -PassThru was specified, don't set apply (unless it was already set)
        }

        foreach ($CurrentSDObject in $InputObject) {
            # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
            # of the loop to prevent unwanted apply actions
            $Apply = $PsBoundParameters.Apply

            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

            $TypeName = $CurrentSDObject.GetType().FullName


            if ($TypeName -eq "System.Security.AccessControl.RegistrySecurity" -or
                $TypeName -match "System.Security.AccessControl.(File|Directory)Security") {

                # For now, only Get-SecurityDescriptor objects are supported
                Write-Warning "'$($MyInvocation.InvocationName)' only supports objects returned from Get-SecurityDescriptor"
                continue
            }
            elseif (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName)) {

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                }
                catch {
                    Write-Error $_
                    return
                }

                # If -PassThru was specified, don't set apply (unless it was already set)
                $Apply = (-not $PassThru) -or $Apply 
            }

            foreach ($PropertyName in $PropertyNames) {
                if ($CurrentSDObject."Are${PropertyName}RulesCanonical" -eq $false) {
                    # Create a temporary SD with a blank ACL:
                    if ($PropertyName -eq "Access") {
                        $TempSd = New-AdaptedSecurityDescriptor -Sddl "D:" -IsContainer:$CurrentSDObject.SecurityDescriptor.IsContainer
                        $AclType = "Discretionary"
                    }
                    else {
                        $TempSd = New-AdaptedSecurityDescriptor -Sddl "S:" -IsContainer:$CurrentSDObject.SecurityDescriptor.IsContainer
                        $AclType = "System"
                    }

                    Add-AccessControlEntry -SDObject $TempSd -AceObject ($CurrentSDObject.Access | where { -not $_.IsInherited })

                    if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, "Replace $AclType ACL with ordered ACL")) {
                        $CurrentSDObject.SecurityDescriptor."${AclType}Acl" = $TempSd.SecurityDescriptor."${AclType}Acl"
                    }

                    if ($Apply) {
                        Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                        $Params = @{
                            __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                            __DefaultReturn = [ref] $__DefaultReturn
                            Action = GetSdString -SDObject $CurrentSDObject
                            Target = $CurrentSDObject.Path
                        }
                        if (CustomShouldProcess @Params) {
                            Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false
                        }
                    }
                    if ($PassThru) {
                        $CurrentSDObject
                    }
                }
                else {
                    # No re-ordering necessary
                }
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Add-AccessControlEntry {

    [CmdletBinding(SupportsShouldProcess=$true)]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Alias('Path')]
        $SDObject,
        [Parameter(Mandatory=$true, ParameterSetName="AceObject", Position=0)]
        [object[]] $AceObject,
        [switch] $AddEvenIfAclDoesntExist,
        [switch] $Apply,
        [switch] $Force,
        [switch] $PassThru,
        [Parameter(ParameterSetName='AceObject')]
        [Parameter(ParameterSetName='GenericAccessMask')]
        [Parameter(ParameterSetName='FileRights')]
        [Parameter(ParameterSetName='FolderRights')]
        [Parameter(ParameterSetName='RegistryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='LogicalShareRights')]
        [Parameter(ParameterSetName='PrinterRights')]
        [Parameter(ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ParameterSetName='ServiceAccessRights')]
        [Parameter(ParameterSetName='ProcessAccessRights')]
        [Alias('Set')]
        [switch] $Overwrite,
# Old dynamic params start here:
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [ValidateSet(
            "AccessAllowed",
            "AccessDenied",
            "SystemAudit"
        )]
        [string] $AceType = "AccessAllowed",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [Alias('IdentityReference','SecurityIdentifier')]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName='FileRights')]
        [Alias('FileSystemRights')]
        [System.Security.AccessControl.FileSystemRights] $FileRights,
        [Parameter(Mandatory=$true, ParameterSetName='FolderRights')]
        [System.Security.AccessControl.FileSystemRights] $FolderRights,
        [Parameter(Mandatory=$true, ParameterSetName='RegistryRights')]
        [System.Security.AccessControl.RegistryRights] $RegistryRights,
        [Parameter(Mandatory=$true, ParameterSetName='ActiveDirectoryRights')]
        [PowerShellAccessControl.ActiveDirectoryRights] $ActiveDirectoryRights,
        [Parameter(Mandatory=$true, ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [int] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [PowerShellAccessControl.AppliesTo] $AppliesTo = "Object",
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [switch] $OnlyApplyToThisContainer,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $ObjectAceType,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $InheritedObjectAceType,
        [Parameter(Mandatory=$true, ParameterSetName='LogicalShareRights')]
        [PowerShellAccessControl.LogicalShareRights] $LogicalShareRights,
        [Parameter(Mandatory=$true, ParameterSetName='PrinterRights')]
        [PowerShellAccessControl.PrinterRights] $PrinterRights,
        [Parameter(Mandatory=$true, ParameterSetName='WmiNameSpaceRights')]
        [PowerShellAccessControl.WmiNamespaceRights] $WmiNameSpaceRights,
        [Parameter(Mandatory=$true, ParameterSetName='ServiceAccessRights')]
        [PowerShellAccessControl.ServiceAccessRights] $ServiceAccessRights,
        [Parameter(Mandatory=$true, ParameterSetName='ProcessAccessRights')]
        [PowerShellAccessControl.ProcessAccessRights] $ProcessAccessRights
    )

<#
    dynamicparam { 
        $DynamicParams = GetNewAceParams -ReplaceAllParameterSets -AllowAliases

        $DynamicParamNames = $DynamicParams.GetEnumerator() | select -exp Key

        $DynamicParams
    }
#>
    dynamicparam {

        # If -AceType is SystemAudit, create -AuditSuccess and -AuditFailure parameters

        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        if ($PSBoundParameters.AceType -eq "SystemAudit") {

            foreach ($ParameterName in "AuditSuccess","AuditFailure") {
                $ParamAttributes = New-Object System.Management.Automation.ParameterAttribute

                # Create the attribute collection (PSv3 allows you to simply cast a single attribute
                # to this type, but that doesn't work in PSv2)
                $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]  # needed for v2
                $AttribColl.Add($ParamAttributes)
                $AttribColl.Add([System.Management.Automation.AliasAttribute] [string[]] ($ParameterName -replace "Audit"))

                $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                    $ParameterName,
                    [switch],
                    $AttribColl
                )
                $DynParamDictionary.Add($ParameterName, $DynamicParameter)
            }
        }
      
        # Return the dynamic parameters
        $DynParamDictionary
    }

    begin {
        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false
        }
    }

    process {

        foreach ($CurrentSDObject in $SDObject) {

            # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
            # of the loop to prevent unwanted apply actions
            $Apply = $PsBoundParameters.Apply

            # If $CurrentSDObject isn't an SD yet, this will get re-assigned later when the SD is obtained
            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

            if ($PSCmdlet.ParameterSetName -ne "AceObject") {
                # User didn't pass an ACE, so they must have provided the parameters to create one.

                try {
                    $PsBoundParameters.GetEnumerator() |
                        where { $__NewAceParameterNames -contains $_.Key } | 
                        foreach -Begin { $NewAceParams = @{} } -Process { $NewAceParams[$_.Key] = $_.Value }
                    
                    $AceObject = New-AccessControlEntry @NewAceParams -ErrorAction Stop
                }
                catch {
                    Write-Error ("You must provide an ACE object to add. Please see the help for Add-AccessControlEntry (Error from New-AccessControlEntry: {0})" -f $_)
                    return
                }
                Write-Verbose "$($MyInvocation.InvocationName): AceObject came through dynamic parameters"
            }
            else {
                Write-Verbose "$($MyInvocation.InvocationName): AceObject came via -AceObject parameter"
            }

            # We've got a collection of AceObjects and the SDObject to apply them to. Go through each
            # ACE now:
            $TypeName = $CurrentSDObject.GetType().FullName

            if ($Overwrite) {
                $AddOrSetMethod = "Set"
            }
            else {
                $AddOrSetMethod = "Add"
            }
            $MethodPartialName = "${AddOrSetMethod}{0}Rule"

            $SdIsDotNetClass = ($TypeName -match "System\.(Security\.AccessControl|DirectoryServices)\.(\w+)Security")
            # Make sure the object is a security descriptor (Get-Acl .NET type SD is fine)
            if (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName) -and
                -not $SdIsDotNetClass) {

                Write-Verbose "$($MyInvocation.InvocationName): SDObject isn't a security descriptor. Attempting to get one from object"

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                }
                catch {
                    Write-Error $_
                    return
                }

                # If -PassThru was specified, don't set apply (unless it was already set)
                $Apply = (-not $PassThru) -or $Apply 

                Write-Verbose "$($MyInvocation.InvocationName):   -> Conversion succeeded; apply set to $Apply"
            }

            foreach ($Ace in $AceObject) {
                # Is this an audit or an access rule? This if statements should determine that:
                if ($Ace.AuditFlags -is [System.Security.AccessControl.AuditFlags] -and $Ace.AuditFlags -ne "None") {
                    $RuleKind = "Audit"
                    $AclType = "SystemAcl"
                }
                else {
                    $RuleKind = "Access"
                    $AclType = "DiscretionaryAcl"
                }

                $MethodName = $MethodPartialName -f $RuleKind
                Write-Verbose "$($MyInvocation.InvocationName): AceType: $RuleKind; Method to invoke: $MethodName"

                
                try {
                    if ($SdIsDotNetClass) {
                        # If SD is native .NET class, the ACE must be in the proper format
                        $Ace = ConvertToSpecificAce -Rules $Ace -AclType $CurrentSDObject.GetType() -ErrorAction Stop
                    }
                    else {
                        # Otherwise, ACE must be CommonAce or ObjectAce
                        $Ace = ConvertToCommonAce $Ace -ErrorAction Stop
                    }
                }
                catch {
                    Write-Error ("{0} (ACE: {1} - {2})" -f $_, $Ace.IdentityReference, $Ace.AccessMask)
                    continue
                }

                # Now we know the method to invoke, and we have a rule that the method can handle:
                $AceDescription = $Ace | GetAceString
                $ShouldProcessAction = "Add ACE: $AceDescription"

                # Make sure the SD contains this type of ACL (this is not actually necessary, but adding an entry to a SD that
                # doesn't contain that type of ACL could overwrite the real ACL. Imagine an elevated user gets an SD w/o the
                # SACL. Then they add an audit rule and apply the changes. If the SACL already had rules, they'll be gone now.
                # For that reason, a user has to specify a special switch to add to a non-existent ACL):
                if (($SdIsDotNetClass -and (($CurrentSDObject | Get-Member -MemberType CodeProperty -Name $RuleKind) -eq $null)) -or
                    ((-not $SdIsDotNetClass) -and ($CurrentSDObject."${RuleKind}Present" -eq $false))) {

                    if (-not $AddEvenIfAclDoesntExist) { # Could be added to if() condition above...
                        Write-Warning "Security descriptor ($($CurrentSDObject.Path)) doesn't contain $AclType section. Make sure the security descriptor was obtained using the -Audit switch, or specify the -AddEvenIfAclDoesntExist switch."
                        continue
                    }
                }

                if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, $ShouldProcessAction)) {
                    try {
                        $CurrentSDObject.$MethodName.Invoke($Ace)
                    }
                    catch {
                        Write-Error $_
                        continue
                    }
                }

            } # end ACE foreach loop

            if ($Apply) {
                Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                $Params = @{
                    __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                    __DefaultReturn = [ref] $__DefaultReturn
                    Action = GetSdString -SDObject $CurrentSDObject
                    Target = $CurrentSDObject.Path
                }
                if (CustomShouldProcess @Params) {
                    Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false
                }
            }
            if ($PassThru) {
                $CurrentSDObject
            }
        }
    }

}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Remove-AccessControlEntry {
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact='Medium')]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        [Alias('Path')]
        $SDObject,
        [Parameter(Mandatory=$true, ParameterSetName='AceObject')]
        [object[]] $AceObject,
        [Parameter(ParameterSetName='RemoveAllEntries')]
        [switch] $RemoveAllAccessEntries,
        [Parameter(ParameterSetName='RemoveAllEntries')]
        [switch] $RemoveAllAuditEntries,
        [Parameter(ParameterSetName='PurgePrincipal')]
        [switch] $PurgeAccessRules,
        [Parameter(ParameterSetName='PurgePrincipal')]
        [switch] $PurgeAuditRules,
        [switch] $Apply,
        [switch] $Force,
        [switch] $PassThru,
        [Parameter(ParameterSetName='AceObject')]
        [Parameter(ParameterSetName='GenericAccessMask')]
        [Parameter(ParameterSetName='FileRights')]
        [Parameter(ParameterSetName='FolderRights')]
        [Parameter(ParameterSetName='RegistryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='LogicalShareRights')]
        [Parameter(ParameterSetName='PrinterRights')]
        [Parameter(ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ParameterSetName='ServiceAccessRights')]
        [Parameter(ParameterSetName='ProcessAccessRights')]
        [switch] $Specific,
# Old dynamic params start here:
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [ValidateSet(
            "AccessAllowed",
            "AccessDenied",
            "SystemAudit"
        )]
        [string] $AceType = "AccessAllowed",
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [Parameter(Mandatory=$true, ParameterSetName='PurgePrincipal')]
        [Alias('IdentityReference','SecurityIdentifier')]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName='FileRights')]
        [Alias('FileSystemRights')]
        [System.Security.AccessControl.FileSystemRights] $FileRights,
        [Parameter(Mandatory=$true, ParameterSetName='FolderRights')]
        [System.Security.AccessControl.FileSystemRights] $FolderRights,
        [Parameter(Mandatory=$true, ParameterSetName='RegistryRights')]
        [System.Security.AccessControl.RegistryRights] $RegistryRights,
        [Parameter(Mandatory=$true, ParameterSetName='ActiveDirectoryRights')]
        [PowerShellAccessControl.ActiveDirectoryRights] $ActiveDirectoryRights,
        [Parameter(Mandatory=$true, ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        [int] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [PowerShellAccessControl.AppliesTo] $AppliesTo = "Object",
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='GenericAccessMask')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FileRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='FolderRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='RegistryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='LogicalShareRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='PrinterRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='WmiNameSpaceRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ServiceAccessRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ProcessAccessRights')]
        [switch] $OnlyApplyToThisContainer,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $ObjectAceType,
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRights')]
        [Parameter(ValueFromPipelineByPropertyName=$true, ParameterSetName='ActiveDirectoryRightsObjectAceType')]
        [Parameter(ParameterSetName='GenericAccessMask', ValueFromPipelineByPropertyName=$true)]
        $InheritedObjectAceType,
        [Parameter(Mandatory=$true, ParameterSetName='LogicalShareRights')]
        [PowerShellAccessControl.LogicalShareRights] $LogicalShareRights,
        [Parameter(Mandatory=$true, ParameterSetName='PrinterRights')]
        [PowerShellAccessControl.PrinterRights] $PrinterRights,
        [Parameter(Mandatory=$true, ParameterSetName='WmiNameSpaceRights')]
        [PowerShellAccessControl.WmiNamespaceRights] $WmiNameSpaceRights,
        [Parameter(Mandatory=$true, ParameterSetName='ServiceAccessRights')]
        [PowerShellAccessControl.ServiceAccessRights] $ServiceAccessRights,
        [Parameter(Mandatory=$true, ParameterSetName='ProcessAccessRights')]
        [PowerShellAccessControl.ProcessAccessRights] $ProcessAccessRights
    )

<#
    dynamicparam { 
        $DynamicParams = GetNewAceParams -ReplaceAllParameterSets

        $DynamicParamNames = $DynamicParams.GetEnumerator() | select -exp Key

        $DynamicParams
    }
#>
    dynamicparam {

        # If -AceType is SystemAudit, create -AuditSuccess and -AuditFailure parameters

        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        if ($PSBoundParameters.AceType -eq "SystemAudit") {

            foreach ($ParameterName in "AuditSuccess","AuditFailure") {
                $ParamAttributes = New-Object System.Management.Automation.ParameterAttribute

                # Create the attribute collection (PSv3 allows you to simply cast a single attribute
                # to this type, but that doesn't work in PSv2)
                $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]  # needed for v2
                $AttribColl.Add($ParamAttributes)
                $AttribColl.Add([System.Management.Automation.AliasAttribute] [string[]] ($ParameterName -replace "Audit"))

                $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                    $ParameterName,
                    [switch],
                    $AttribColl
                )
                $DynParamDictionary.Add($ParameterName, $DynamicParameter)
            }
        }
      
        # Return the dynamic parameters
        $DynParamDictionary
    }

    begin {
        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false
        }
    }

    process {
        foreach ($CurrentSDObject in $SDObject) {
            # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
            # of the loop to prevent unwanted apply actions
            $Apply = $PsBoundParameters.Apply

            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

            if ("AceObject","RemoveAllEntries", "PurgePrincipal" -notcontains $PSCmdlet.ParameterSetName) {
                # If the param set isn't one of these, that means ACE object params were provided 
                # through the dynamic parameters. Call AceObject w/ the bound parameters:

                try {
                    $PsBoundParameters.GetEnumerator() |
                        where { $__NewAceParameterNames -contains $_.Key } | 
                        foreach -Begin { $NewAceParams = @{} } -Process { $NewAceParams[$_.Key] = $_.Value }
                    
                    $AceObject = New-AccessControlEntry @NewAceParams -ErrorAction Stop
                }
                catch {
                    Write-Error "You must provide an ACE object to remove. Please see the help for Remove-AccessControlEntry"
                    return
                }
            }

            # We've got a collection of AceObjects and the SDObject to apply them to. Go through each
            # ACE now:
            $TypeName = $CurrentSDObject.GetType().FullName

            $MethodPartialName = "Remove{0}Rule"

            $SdIsDotNetClass = ($TypeName -match "System\.(Security\.AccessControl|DirectoryServices)\.(\w+)Security")
            # Make sure the object is a security descriptor (Get-Acl .NET type SD is fine)
            if (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName) -and
                -not $SdIsDotNetClass) {

                Write-Verbose "$($MyInvocation.InvocationName): SDObject isn't a security descriptor. Attempting to get one from object"

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                }
                catch {
                    Write-Error $_
                    return
                }

                # If -PassThru was specified, don't set apply (unless it was already set)
                $Apply = (-not $PassThru) -or $Apply 

                Write-Verbose "$($MyInvocation.InvocationName):   -> Conversion succeeded; apply set to $Apply"
            }

            if ($PSCmdlet.ParameterSetName -eq "PurgePrincipal") {
                # Call purge method on each object:
                $MethodsToCall = @()
                if ($PurgeAuditRules) {
                    $MethodsToCall += "PurgeAuditRules"
                }
                if ($PurgeAccessRules -or (-not $MethodsToCall)) {
                    # If -PurgeAuditRules wasn't passed, we'll have to run as
                    # though -PurgeAccessRules was passed
                    $MethodsToCall += "PurgeAccessRules" 
                }

                foreach ($Method in $MethodsToCall) {
                    if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, "Invoke $Method for $Principal principal")) {
                        $CurrentSDObject.$Method.Invoke(($Principal | ConvertToIdentityReference))
                    }
                }
            }
            else {

                if ($PSCmdlet.ParameterSetName -eq "RemoveAllEntries") {
                    # Just make the $AceObject collection every ACL entry. Alternative would be to create
                    # blank ACL objects, but then there would have to be more logic. If this ends up being
                    # really slow, I'll investigate the alternate method
                    $AceObject = @()
                    if ($RemoveAllAccessEntries) {
                        $AceObject += $CurrentSDObject.Access
                    }

                    if ($RemoveAllAuditEntries) {
                        $AceObject += $CurrentSDObject.Audit
                    }
                }

                foreach ($Ace in $AceObject) {
                    # Is this an audit or an access rule? These if statements should determine that:
                    if ($Ace.AuditFlags -is [System.Security.AccessControl.AuditFlags] -and $Ace.AuditFlags -ne "None") {
                        $RuleKind = "Audit"
                        $AclType = "SystemAcl"
                    }
                    else {
                        $RuleKind = "Access"
                        $AclType = "DiscretionaryAcl"
                    }

                    $MethodName = $MethodPartialName -f $RuleKind

                    # If -Specific switch was supplied, append 'Specific' to the MethodName
                    if ($Specific) {
                        $MethodName = "${MethodName}Specific"
                    }

                    try {
                        if ($SdIsDotNetClass) {
                            # If SD is native .NET class, the ACE must be in the proper format
                            $Ace = ConvertToSpecificAce -Rules $Ace -AclType $CurrentSDObject.GetType() -ErrorAction Stop
                        }
                        else {
                            # Otherwise, ACE must be CommonAce or ObjectAce
                            $Ace = ConvertToCommonAce $Ace -ErrorAction Stop
                        }
                    }
                    catch {
                        Write-Error ("{0} (ACE: {1} - {2})" -f $_, $Ace.IdentityReference, $Ace.AccessMask)
                        continue
                    }

                    # Now we know the method to invoke, and we have a rule that the method can handle:

                    $AceDescription = $Ace | GetAceString
                    $ShouldProcessAction = "Remove ACE: $AceDescription"

                    if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, $ShouldProcessAction)) {
                        try {
                            [void] $CurrentSDObject.$MethodName.Invoke($Ace)
                        }
                        catch {
                            Write-Error $_
                            continue
                        }
                    }

                } # end ACE foreach loop
            } # end else (after check for purge param set)

            if ($Apply) {
                Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                $Params = @{
                    __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                    __DefaultReturn = [ref] $__DefaultReturn
                    Action = GetSdString -SDObject $CurrentSDObject
                    Target = $CurrentSDObject.Path
                }
                if (CustomShouldProcess @Params) {
                    Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false
                }
            }
            if ($PassThru) {
                $CurrentSDObject
            }
        } # end SDObject foreach loop
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Set-Owner {

    [CmdletBinding(DefaultParameterSetName='Path', SupportsShouldProcess=$true)]
    param(
        [Parameter(Position=0)]
        [Alias('User','Group','IdentityReference')]
        # The object that this ACE will apply to. This can be a string representing a user, group,
        # or SID. It can also be a [System.Security.Principal.NTAccount] or a
        # [System.Security.Principal.SecurityIdentifier] object.
        $Principal = $env:USERNAME,
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias('SDObject')]
        $InputObject,
        [Parameter(Mandatory=$true, ParameterSetName='Path', ValueFromPipelineByPropertyName=$true)]
        [Parameter(Mandatory=$true, ParameterSetName='DirectPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path,
        [Parameter(Mandatory=$true, ParameterSetName='DirectPath')]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [Parameter(ParameterSetName='DirectPath')]
        [switch] $IsContainer = $false,
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [switch] $Apply,
        [switch] $Force,
        [switch] $PassThru
    )

    begin {
        <#
        See the note at the beginning of the CustomShouldProcess function for more info about why I've (hopefully temporarily)
        implemented my own ShouldProcess function inside the SD modification functions.
        #>

        if ($Force) {
            $__CustomConfirmImpact = [System.Management.Automation.ConfirmImpact]::None
            $__DefaultReturn = $true
        }
        else {
            $__CustomConfirmImpact = $__ConfirmImpactForApplySdModification
            $__DefaultReturn = $false
        }
    }
    process {
        $Principal = $Principal | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop

        try {
            $TranslatedPrincipal = $Principal | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
        }
        catch {
            Write-Error $_
            return
        }

        $ShouldProcessAction = "Set owner to '$Principal'"
        switch ($PSCmdlet.ParameterSetName) {
            "InputObject" {
                # An object was passed to the function. After a little param validation, do the
                # same thing that .SetOwner() method would do on a Get-Acl object, i.e., simply
                # change the owner on the in memory SD object:

                $MethodName = "SetOwner" # The method that will be invoked on SD objects

                foreach ($CurrentSDObject in $InputObject) {
                    # This can get set later if $SDObject isn't a security descriptor; reset it at the beginning
                    # of the loop to prevent unwanted apply actions
                    $Apply = $PsBoundParameters.Apply

                    $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path

                    $TypeName = $CurrentSDObject.GetType().FullName
                    if ($TypeName -eq "System.Security.AccessControl.RegistrySecurity" -or
                        $TypeName -match "System.Security.AccessControl.(File|Directory)Security") {

                        # The SDObject is a .NET file or registry security object from Get-Acl
                        # This is fine, and no extra work should be necessary b/c the methods that
                        # will be called are the same for Get-Acl objects and Get-SD objects
                    }
                    elseif (-not ($CurrentSDObject.pstypenames -contains $__AdaptedSecurityDescriptorTypeName)) {

                        try {
                            # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                            $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                            $ShouldProcessTarget = "{0} (in memory SD)" -f $CurrentSDObject.Path
                        }
                        catch {
                            Write-Error $_
                            return
                        }

                        # If -PassThru was specified, don't set apply (unless it was already set)
                        $Apply = (-not $PassThru) -or $Apply
                    }

                    if ($PSCmdlet.ShouldProcess($ShouldProcessTarget, "Invoke $MethodName method")) {
                        $CurrentSDObject.$MethodName.Invoke($TranslatedPrincipal)
                    }

                    if ($Apply) {
                        Write-Verbose "$($MyInvocation.InvocationName): Apply set, so SD is being applied"
                
                        $Params = @{
                            __CustomConfirmImpact = [ref] $__CustomConfirmImpact
                            __DefaultReturn = [ref] $__DefaultReturn
                            Action = GetSdString -SDObject $CurrentSDObject -SecurityInformation Owner
                            Target = $CurrentSDObject.Path
                        }
                        if (CustomShouldProcess @Params) {
                            Set-SecurityDescriptor -SDObject $CurrentSDObject -Confirm:$false -WhatIf:$false -Sections Owner
                        }
                    }
                    if ($PassThru) {
                        $CurrentSDObject
                        Write-Warning ("Please apply the security descriptor for '{0}' and get it again to reflect any inherited entries" -f $CurrentSDObject.Path)
                    }
                }
            }

            { $_ -eq "Path" -or $_ -eq "LiteralPath" -or $_ -eq "DirectPath" } {

                # This looks a little weird, but what's happening is simple:
                # We're going to create a temporary SD that only has an owner. To do that, we need
                # to get the path information (including object type, etc), then feed that into the
                # New-Adapted.... function, and then we'll call Set-Owner on that. We want the same
                # parameters passed to it (except we're adding an -Apply parameter), but we can't pass
                # the Path (or LiteralPath) back to it. For that reason, we remove the *Path property,
                # then splat $PSboundParameters to Set-Owner.
                $PathPropertyName = $PSCmdlet.ParameterSetName -replace "^Direct"
                $ExtraParam = @{ $PathPropertyName = $PSBoundParameters.$PathPropertyName }
                $null = $PSBoundParameters.Remove($PathPropertyName)

                $PSBoundParameters.Apply = (-not $PassThru) -or ($Apply)
                # Create a SD with an owner and a blank DACL (don't worry, Set-Owner only sets the owner; the blank DACL is
                # there to prevent having an ACE that gives everyone allow permissions [which still wouldn't matter, but
                # who cares?])
                $PathInfo = GetPathInformation @PSBoundParameters @ExtraParam
                $null = $PathInfo.Remove("InputObject")
                New-AdaptedSecurityDescriptor -Sddl "O:${TranslatedPrincipal}D:" @PathInfo| Set-Owner @PSBoundParameters
                return
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-EffectiveAccess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        [Alias("SDObject")]
        $InputObject,
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Alias('User', 'Group', 'IdentityReference')]
        [string[]] $Principal = $env:USERNAME,
        [switch] $ListAllRights,
        # Used for AD objects
        $ObjectAceTypes
    )


    process {
        if ($PSCmdlet.ParameterSetName -eq "Path" -and (-not $PSBoundParameters.ContainsKey("Path"))) {
            # GetPathInformation uses PSBoundParameters, so set it up as if the default path was passed
            # as a bound parameter:
            $null = $PSBoundParameters.Add("Path", $Path)
        }

        if ($PSCmdlet.ParameterSetName -ne "InputObject") {
            $Params = @{
                $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
            }

            $InputObject = Get-SecurityDescriptor @Params -ErrorAction Stop
        }

        foreach ($CurrentSDObject in $InputObject) {
            if ($CurrentSDObject.pstypenames -notcontains $__AdaptedSecurityDescriptorTypeName) {

                try {
                    # Not an object from Get-SecurityDescriptor, so see if it can be converted:
                    $CurrentSDObject = Get-SecurityDescriptor -InputObject $CurrentSDObject -ErrorAction Stop 
                }
                catch {
                    Write-Error $_
                    return
                }
            }

            $AccessMaskEnumeration = $CurrentSDObject.GetAccessMaskEnumeration()

            if ($AccessMaskEnumeration -eq $null) {
                $AccessMaskEnumeration = [int]
            }

            # The AuthZ AccessCheck takes a requested access and returns the actual access. There is a special
            # requested access that means check for the maximum allowed: 0x02000000
            # For now, use that (in the future, maybe the functionc an take this as a parameter
            $DesiredAccess = 0x02000000 # MAX ALLOWED
            $TypeName = $__EffectiveAccessTypeName
            
            # AuthzAccessCheck is called against a binary security descriptor. File and folder objects can
            # have multiple SDs (NTFS permissions, share permissions, and any number of central access
            # rules). Store each of those in a hash table (the key allows us to show where each right is
            # being limited), and call AuthzAccessCheck on each one.
            if ($CurrentSDObject.ObjectType -eq 'FileObject' -and (-not $ListAllRights) -and ($__OsVersion -gt "6.2")) {
                # If -ListAllRights isn't specified, AuthzAccessCheck will show true effective rights if
                # Attribute and Scope are in the SD
                $SdBytes = GetSecurityInfo -Path $CurrentSDObject.SdPath -ObjectType $CurrentSDObject.ObjectType -SecurityInformation Owner, Group, Dacl, Attribute, Scope

                # Windows 8 or higher supports CAP and object attributes, so get that information and add it to $SdBytes.
                #
                # NOTE: The correct way to do this is get the binary form of the extra info and pass it into the OptionalSecurityDescriptorArray
                #       argument, but that's not currently working. I suspect that more manual memory allocation and layout is required, so I'm
                #       taking the easy way out for now and simply modifying the entire SD
            }
            else {
                $SdBytes = $CurrentSDObject.GetSecurityDescriptorBinaryForm()
            }

            # AuthzAccessCheck is going to be called against all security descriptors in this hash table. For now,
            # files/folders should be the only objects that have multiple security descriptors, so most objects
            # will only have the "Object Permissions" security descriptor.
            #
            # Files and folders can have multiple layers of security:
            #   - Object Permissions
            #   - Share Permissions
            #   - Central Access Policy
            #       - Central Access Rules (more than one)
            #
            # Naming the SD in this hash table allows the -ListAllRights option to show the user why a right
            # is denied/limited.
            $SecurityDescriptorsToCheck = @{
                "Object Permissions" = $SdBytes
            }

            if ($CurrentSDObject.ObjectType -eq 'FileObject') {
                # Check to see if this is a share:
                if ($CurrentSDObject.SdPath -match "(?<sharepath>\\\\[^\\]+\\[^\\]+)") {
                    try {
                        $ShareSd = Get-SecurityDescriptor -Path $Matches.sharepath -ObjectType LMShare -ErrorAction Stop
                        $NewSd = New-AdaptedSecurityDescriptor -Sddl "D:" -IsContainer
                        $NewSd.SecurityDescriptor.Owner = $ShareSd.Owner | ConvertToIdentityReference -ReturnSid
                        $NewSd.SecurityDescriptor.Group = $ShareSd.Group | ConvertToIdentityReference -ReturnSid

                        $ShareSd.Access | ForEach-Object {
                            $TranslatedFolderRights = $_.AccessMaskDisplay -replace "Change", "Modify"

                            $NewSd | Add-AccessControlEntry -Principal $_.Principal -FolderRights $TranslatedFolderRights -ErrorAction Stop
                        }
                        
                        $SecurityDescriptorsToCheck."Share Permissions" = $NewSd.GetSecurityDescriptorBinaryForm()
                    }
                    catch {
                        Write-Debug ("{0}: Failed to get share permissions for {1}" -f $MyInvocation.MyCommand, $Matches.sharepath)
                    }
                }

#$SecurityDescriptorsToCheck."Test Alternate SD" = (Get-SecurityDescriptor C:\windows).GetSecurityDescriptorBinaryForm()

                <# 
                Check for Central Access Policies here:
                  - If there is a CAP, go through each central access rule
                  - For each rule, check to see if there is a condition that must be met and evaluate it
                  - If condition is met, add a security descriptor to the hash table that includes the DACL
                  - Get OptionalSecurityDescriptor working in the AuthzAccessCheck() call, or manually add
                    attribute information to the SACL of the SD being added to the hash table (attribute info
                    must be passed to AuthzAccessCheck)
                #>
            }

            foreach ($CurrentIdentityReference in $Principal) {
                $CurrentIdentityReference = $CurrentIdentityReference | ConvertToIdentityReference -ReturnAccount -DontVerifyNtAccount

                try {
                    $Sid = $CurrentIdentityReference | ConvertToIdentityReference -ReturnSid -ErrorAction Stop
                    $SidBytes = New-Object byte[] $Sid.BinaryLength
                    $Sid.GetBinaryForm($SidBytes, 0)
                }
                catch {
                    Write-Error "Error translating '$CurrentIdentityReference' to SID: $_"
                    continue
                }

                # Build the request object
                $Request = New-Object PowerShellAccessControl.PInvoke.authz+AUTHZ_ACCESS_REQUEST
                $Request.DesiredAccess = $DesiredAccess

                #region DSObject Request object
                if ($CurrentSDObject.ObjectType -match "^DSObject") {
                    # SD belongs to an AD object. AD objects can have much more complicated request objects
                    # if we're going to check at the property level.

                    [PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST[]] $ObjectTypeListArray = @()
                    $ObjectTypeList = New-Object PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST

                    # The object's type GUID always goes at level 0 (I think this is so the API will be
                    # able to check an ACE's InheritedObjectAceType to see when an ACE applies to this
                    # object)
                    $ObjectTypeList.Level = 0
                    $ObjectType = (Get-ADObjectAceGuid -Name $CurrentSDObject.DsObjectClass -TypesToSearch ClassObject | select -first 1 -exp guid).ToByteArray()
                    $Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                    [System.Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                    $ObjectTypeList.ObjectType = $Ptr
                    $ObjectTypeListArray += $ObjectTypeList


                    Write-Verbose "$(Get-Date): Grouping requested properties by PropertySet"
                    $GroupedProperties = $ObjectAceTypes | Where-Object { $_ } | ForEach-Object {

                        # User passed something to the -ObjectAceTypes function. Wildcards are allowed in strings passed, so it's
                        # possible that the list of ObjectAceTypes is going to get HUGE (especially if the * string is passed,
                        # which would mean show effective access for ALL ObjectAceTypes.
                        #
                        # The longest part of doing that is figuring out the Property and PropertySet relationships, so those are
                        # cached if the list of objects grows large enough (an arbitrary number below)
                        if ($__GroupedPropertyCache.ContainsKey($_)) {
                            Write-Verbose "$($MyInvocation.MyCommand): ObjectAceType '$_' results have been previously cached"
                            $__GroupedPropertyCache.$_
                        }
                        else {
                            # Not cached, so get the information
                            $Params = @{
                                TypesToSearch = "Property"
                            }

                            if ($_ -is [PSObject] -and $_.Guid -is [guid]) {
                                $Params.Guid = $_.Guid
                            }
                            else {
                                $Guid = $_ -as [guid]
                                if ($Guid) {
                                    $Params.Guid = $Guid
                                }
                                else {
                                    $Params.Name = "^{0}$" -f $_.ToString()
                                }

                                $Properties = Get-ADObjectAceGuid @Params

                                $CurrentGroupedProperties = $Properties | ForEach-Object -Begin { $Count = 0 } -Process {
                                    Write-Progress -Activity "Building property list" -Status ("Current property: {0}" -f $_.Name) -PercentComplete (($Count++/$Properties.Count) * 100)
                                    New-Object PSObject -Property @{
                                        Property = $_.Guid
                                        PropertySet = (LookupPropertySet -Property $_.Guid | select -exp Value -ErrorAction SilentlyContinue)
                                    }
                                } -End { Write-Progress -Completed -Activity "Building property list" -Status "" } | Group-Object PropertySet

                                $__PropertyCountToCache = 1000
                                if ($Properties.Count -gt $__PropertyCountToCache) {
                                    Write-Verbose "$($MyInvocation.MyCommand): Property count for ObjectAceType '$_' is $($Properties.Count); adding to cache"
                                    $__GroupedPropertyCache.$_ = $CurrentGroupedProperties
                                }

                                $CurrentGroupedProperties
                            }
                        }
                    }

                    # This next part adds each property (and its propery set) to the $ObjectTypeListArray.
                    # The .Level property will be 1 for properties w/o a property set, and 2 for properties
                    # w/ a property set (the property set will be at level 1). This will output any encountered
                    # property sets so any property sets that we can compare that list with all requested
                    # property sets in a little bit.
                    $RequestedPropertiesPropertySets = $GroupedProperties | ForEach-Object {

                        # Name property contains the PropertySet guid and the group property contains
                        # the property guids
                        if ($_.Name -eq "") {
                            # Properties with a null PropertySet don't belong to one. They will be at
                            # level 1 in the tree
                            $Level = 1
                        }
                        else {
                            # Set up the property set first, then go through all properties
                            $ObjectTypeList.Level = 1
                            $ObjectType = ([guid] $_.Name).ToByteArray()
                            $Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                            [System.Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                            $ObjectTypeList.ObjectType = $Ptr
                            $ObjectTypeListArray += $ObjectTypeList

                            # Properties will be at this level:
                            $Level = 2

                            # Output this so that a list of used PropertySets can be maintained. If the $RequestedPropertySets
                            # contains GUIDs that aren't encountered while building the properties, then they will be added
                            # to the tree later
                            $_.Name
                        }

                        $_.Group | Select-Object -exp Property | ForEach-Object { 
                            $ObjectTypeList.Level = $Level
                            $ObjectType = ([guid] $_).ToByteArray()
                            $Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                            [System.Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                            $ObjectTypeList.ObjectType = $Ptr
                            $ObjectTypeListArray += $ObjectTypeList
                        }
                    }

                    # We've got a list of all of the properties that the user is after, and they are now grouped
                    # by their property set (properties with no property set show a $null property set). Now get
                    # any other object types requested:
                    Write-Verbose "$(Get-Date): Getting non-property object types"
                    $NonPropertyObjectAceTypes = $ObjectAceTypes | Where-Object { $_ } | ForEach-Object {
                        $Params = @{
                            TypesToSearch = "ClassObject", "ExtendedRight", "ValidatedWrite", "PropertySet"
                        }

                        if ($_ -is [PSObject] -and $_.Guid -is [guid]) {
                            $Params.Guid = $_.Guid
                        }
                        else {
                            $Guid = $_ -as [guid]
                            if ($Guid) {
                                $Params.Guid = $Guid
                            }
                            else {
                                $Params.Name = $_.ToString()
                            }
                        }

                        Get-ADObjectAceGuid @Params
                    }

                    # Now it's time to add any PropertySets that were requested that haven't been added yet
                    Write-Verbose "$(Get-Date): Getting any property sets that weren't already found"
                    $RefObject = $NonPropertyObjectAceTypes | Where-Object { $_.Type -eq "PropertySet" } | select -ExpandProperty Guid

                    # These next two variables should be null b/c of compare-object call
                    if (-not $RefObject) { $RefObject = @() }
                    if (-not $RequestedPropertiesPropertySets) { $RequestedPropertiesPropertySets = @() }
                    Write-Verbose "$(Get-Date): Getting any property sets that weren't already found (using compare-object)"
                    Compare-Object -ReferenceObject $RefObject -DifferenceObject $RequestedPropertiesPropertySets |
                        Where-Object { $_.SideIndicator -eq "<=" } | ForEach-Object {
                                $ObjectTypeList.Level = 1
                                $ObjectType = ([guid] $_.InputObject).ToByteArray()
                                $Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                                [System.Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                                $ObjectTypeList.ObjectType = $Ptr
                                $ObjectTypeListArray += $ObjectTypeList
                        }

                    # Finally, add any object types that have been requested that are not properties or property sets:
                    Write-Verbose "$(Get-Date): Getting non-property objects"
                    $NonPropertyObjectAceTypes | Where-Object { $_.Type -notmatch "^Property" } | ForEach-Object {
                        $ObjectTypeList.Level = 1
                        $ObjectType = ([guid] $_.Guid).ToByteArray()
                        $Ptr = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($ObjectType.Count)
                        [System.Runtime.InteropServices.Marshal]::Copy($ObjectType, 0, $Ptr, $ObjectType.Count)
                        $ObjectTypeList.ObjectType = $Ptr
                        $ObjectTypeListArray += $ObjectTypeList
                    }

                    # Now, unfortunately, we've got to manually allocate the memory for the OBJECT_TYPE_LIST:
                    $SizeOfStruct = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PowerShellAccessControl.PInvoke.authz+OBJECT_TYPE_LIST])
                    $ptrObjectTypeListArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($SizeOfStruct * $ObjectTypeListArray.Count)
                    for ($i = 0; $i -lt $ObjectTypeListArray.Count; $i++) {
                        $ptrObjectTypeList = $ptrObjectTypeListArray.ToInt64() + ($SizeOfStruct * $i)
                        [System.Runtime.InteropServices.Marshal]::StructureToPtr($ObjectTypeListArray[$i], $ptrObjectTypeList, $false)
                    }

                    $Request.ObjectTypeList = $ptrObjectTypeListArray
                    $Request.ObjectTypeListLength = $ObjectTypeListArray.Count
                }
                #endregion

                # Build the reply object. The ResultListLength property depends on the ObjectTypeListLength
                # in the request object (if it's not a AD object and it is 0, then the ResultListLength
                # is 1)
                $ResultListLength = $Request.ObjectTypeListLength
                if ($ResultListLength -eq 0) { $ResultListLength = 1 }

                $Reply = New-Object PowerShellAccessControl.PInvoke.authz+AUTHZ_ACCESS_REPLY
                $Reply.ResultListLength = $ResultListLength
                $Reply.Error = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Reply.ResultListLength * [System.Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32]))
                $Reply.GrantedAccessMask = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Reply.ResultListLength * [System.Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32]))
                $Reply.SaclEvaluationResults = [System.IntPtr]::Zero #[System.Runtime.InteropServices.Marshal]::AllocHGlobal($Reply.ResultListLength * [System.Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32]))

                try {
                    # Get a resource manager handle. This isn't the best place for this b/c it causes the
                    # handle to be opened and freed for each principal and for each security descriptor. This
                    # belongs in the begin block. That will happen one day when the function is restructured.
                    $hResourceManager = [System.IntPtr]::Zero
                    [PowerShellAccessControl.PInvoke.authz]::AuthzInitializeResourceManager(
                        [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzResourceManagerFlags]::NoAudit, # Flags
                        [System.IntPtr]::Zero,  # Access check callback function (Not used here)
                        [System.IntPtr]::Zero,  # Dynamic groups callback function (Not used here)
                        [System.IntPtr]::Zero,  # Callback function to free memory from previous callback (Not used here)
                        "",                     # Resource manager name
                        [ref] $hResourceManager # Resource manager handle that we're after :)
                    ) | CheckExitCode -ErrorAction Stop -Action "Initializing resource manager"

                    
                    # Get a client context handle
                    $hClientContext = [System.IntPtr]::Zero
                    $UnusedId = New-Object PowerShellAccessControl.PInvoke.authz+LUID
                    [PowerShellAccessControl.PInvoke.authz]::AuthzInitializeContextFromSid(
                        [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzContextFlags]::None,  # Flags; none for now. If S4U logon not available, some groups are omitted. See http://msdn.microsoft.com/en-us/library/windows/desktop/aa376309(v=vs.85).aspx
                        $SidBytes,               # Sid to create the context for
                        $hResourceManager,       # Resource manager handle
                        [System.IntPtr]::Zero,   # Expiration time (not enforced, so not using; if ever use, need to update PInvoke signature)
                        $UnusedId,               # This param isn't currently used; can probably update PInvoke signature to not require LUID signature and creation
                        [System.IntPtr]::Zero,   # Dynamic groups callback arguments (Not used here)
                        [ref] $hClientContext    # The returned handle
                    ) | CheckExitCode -ErrorAction Stop -Action "Initializing context from SID"


                    # Build a script block to do the AuthzAccessCheck. SB is used instead of directly calling it b/c
                    # sometimes a Group-Object call is added between calling AuthzAccessCheck() and crafting the
                    # output objects. That would introduce a significant delay for AD objects w/ large request objects. 
                    $SecurityDescriptorsToCheck.GetEnumerator() | ForEach-Object {
                        $CurrentSdEntry = $_

                        Write-Debug "Calling AuthzAccessCheck"
                        [PowerShellAccessControl.PInvoke.authz]::AuthzAccessCheck(
                            [PowerShellAccessControl.PInvoke.AuthZEnums.AuthzAccessCheckFlags]::None,  # Flags
                            $hClientContext,       # Client context handle
                            [ref] $Request, 
                            [System.IntPtr]::Zero, # Audit event (not used here)
                            $CurrentSdEntry.Value, # Binary form of SD
                            $null,                 # Optional security descriptors
                            0,                     # Optional SD count (see previous argument)
                            [ref] $Reply,          # 
                            [ref] [System.IntPtr]::Zero  # Check results (Used for caching??)
                        ) | CheckExitCode -ErrorAction Stop -Action "Performing access check"

<#
# GrantedMask and ErrorCode are returned as pointers, so read the Int32 value from where they point:
$GrantedMask = [System.Runtime.InteropServices.Marshal]::ReadInt32($Reply.GrantedAccessMask)
$ErrorCode = [System.Runtime.InteropServices.Marshal]::ReadInt32($Reply.Error)
$ErrorMessage = ([System.ComponentModel.Win32Exception] $ErrorCode).Message
#>
                        $OutputProperties = @{
                            DisplayName = $CurrentSDObject.DisplayName
                            IdentityReference = $CurrentIdentityReference
                            #MessageDebug = $ErrorMessage
                        }

                        # Go through each reply (if the object wasn't an AD object or there were no -ObjectAceTypes provided, there
                        # will only be one reply)
                        $SizeOfInt = [System.Runtime.InteropServices.Marshal]::SizeOf([type] [UInt32])
                        for ($i = 0; $i -lt $Reply.ResultListLength; $i++) {

                            # GrantedMask and ErrorCode are returned as pointers, so read the Int32 value from where they point:
                            $GrantedMask = [System.Runtime.InteropServices.Marshal]::ReadInt32($Reply.GrantedAccessMask.ToInt64() + ($i * $SizeOfInt))
                            $ErrorCode = [System.Runtime.InteropServices.Marshal]::ReadInt32($Reply.Error.ToInt64() + ($i * $SizeOfInt))
                            $ErrorMessage = ([System.ComponentModel.Win32Exception] $ErrorCode).Message


<#
                            # If there was no granted access for this ObjectType (only ObjectTypes should be affected b/c $i 
                            # must be greater than 0) and -ListAllRights wasn't specified, then don't even output an object
                            if ($GrantedMask -eq 0 -and $i -gt 0) {
                                continue
                            }
#>

                            # Only look at replies after the first one (so only AD objects)
                            if ($ObjectTypeListArray -and ($i -gt 0)) {
                                $Guid = [System.Runtime.InteropServices.Marshal]::PtrToStructure($ObjectTypeListArray[$i].ObjectType, [type][guid])
                            }
                            else {
                                $Guid = [guid]::Empty
                            }

                            $OutputProperties = @{
                                Guid = $Guid
                                Permission = $GrantedMask
                                LimitedBy = $CurrentSdEntry.Name
                            }

                            New-Object PSObject -Property $OutputProperties
                        }
                    } | Group-Object Guid | ForEach-Object {
                        $Group = @($_.Group)

                        $OutputProperties = @{
                            DisplayName = $CurrentSDObject.DisplayName
                            IdentityReference = $CurrentIdentityReference
                        }

                        $GetPermissionParams = @{
                            AccessMaskEnumeration = $AccessMaskEnumeration
                        }

                        if (-not $ListAllRights) {
                            $TypeName = $__EffectiveAccessTypeName

                            $CombinedEffectiveAccess = [int32]::MaxValue
                            foreach ($GroupItem in $Group) {
                                $CombinedEffectiveAccess = $CombinedEffectiveAccess -band $GroupItem.Permission
                            }
                            $GetPermissionParams.AccessMask = $CombinedEffectiveAccess
                            $GetPermissionParams.ObjectAceType = $Group[0].Guid
                            $OutputProperties.EffectiveAccess = GetPermissionString @GetPermissionParams

                            if ($OutputProperties.EffectiveAccess -eq "None") {
                                return
                            }

                            $ReturnObject = New-Object PSObject -Property $OutputProperties
                            $ReturnObject.pstypenames.Insert(0, $TypeName)
                            $ReturnObject
                        }
                        else {
                            $TypeName = $__EffectiveAccessListAllTypeName

                            $LimitedBy = @()
                            $AccessAllowed = $true
                            $GetPermissionParams.ObjectAceType = $Group[0].Guid
                            $GetPermissionParams.ListEffectivePermissionMode = $true
                            $Group | Where-Object { $_ } | ForEach-Object {
                                $GroupItem = $_

                                $GetPermissionParams.AccessMask = $GroupItem.Permission
                                GetPermissionString @GetPermissionParams | 
                                    Add-Member -MemberType NoteProperty -Name LimitedBy -Value $GroupItem.LimitedBy -PassThru |
                                    Add-Member -MemberType NoteProperty -Name AccessMask -Value $GroupItem.Permission -PassThru
                            } | Group-Object Permission | ForEach-Object {
                                $Allowed = $true
                                $LimitedBy = @()
                                foreach ($PermissionGroup in $_.Group) {
                                    if (-not $PermissionGroup.Allowed) {
                                        $Allowed = $false
                                        $LimitedBy += $PermissionGroup.LimitedBy
                                    }
                                }

                                $OutputProperties.Allowed = $Allowed
                                $OutputProperties.Permission = $_.Name
                                $OutputProperties.LimitedBy = $LimitedBy -join ", "

                                $ReturnObject = New-Object PSObject -Property $OutputProperties
                                $ReturnObject.pstypenames.Insert(0, $TypeName)
                                $ReturnObject

                            }
                        }

                    }

                }
                catch {
                    Write-Error $_
                    continue
                }
                finally {
Write-Verbose "Freeing effective access stuff"
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Reply.Error)
                    [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Reply.GrantedAccessMask)

                    $ObjectTypeListArray | Where-Object { $_ } | ForEach-Object {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($_.ObjectType)
                    }

                    if ($Request.ObjectTypeList -ne [System.IntPtr]::Zero) {
                        [System.Runtime.InteropServices.Marshal]::FreeHGlobal($Request.ObjectTypeList)
                    }

                    if ($hClientContext -ne [System.IntPtr]::Zero) {
                        [PowerShellAccessControl.PInvoke.authz]::AuthzFreeContext($hClientContext) | CheckExitCode -Action "Freeing AuthZ client context"
                    }
                    if ($hResourceManager -ne [System.IntPtr]::Zero) {
                        [PowerShellAccessControl.PInvoke.authz]::AuthzFreeResourceManager($hResourceManager) | CheckExitCode -Action "Freeing AuthZ resource manager"
                    }
                }
            }
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-MandatoryIntegrityLabel {

    [CmdletBinding(DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        $InputObject,
        [Parameter(ParameterSetName='DirectPath', Position=0, ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipelineByPropertyName=$true)]
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        [string[]] $LiteralPath,
        [Parameter(ParameterSetName='DirectPath')]
        [System.Security.AccessControl.ResourceType] $ObjectType
    )

    process {
        foreach ($PathInfo in GetPathInformation @PSBoundParameters) {

            # See this link for background on what's about to happen:
            # http://msdn.microsoft.com/en-us/library/windows/desktop/aa965848(v=vs.85).aspx

            # Call GetSecurityInfo, but only asking for Label information. This should give an SD that has a SACL with a special
            # ACE (or an empty SACL if there is no MIL):
            $SecInfoParams = @{
                ObjectType = $PathInfo.ObjectType
                SecurityInformation = "Label"
                ErrorAction = "Stop"
            }
            if ($PathInfo.Handle -ne $null) {
                $SecInfoParams.Handle = $PathInfo.Handle
            }
            else  {
                $SecInfoParams.Path = $PathInfo.SdPath
            }
            
            try {
                $BinLabelInfo = GetSecurityInfo @SecInfoParams
            }
            catch {
                Write-Error $_
                continue
            }

            # This could go through the New-AdaptedSecurityDescriptor, but that's just going to add lots of extra work, and
            # it wouldn't be able to view the SACL's ACE anyway (not from the .Audit property). For that reason, just make it
            # a RawSecurityDescriptor object
            $SD = New-Object System.Security.AccessControl.RawSecurityDescriptor (([byte[]] $BinLabelInfo), 0)

            # AceType of 17 is what holds the info we want:
            $SD.SystemAcl | 
                where { [int] $_.AceType -eq 17 } |
                ForEach-Object {

                    $Data = $_.GetOpaque()
                    $AccessMask = [System.BitConverter]::ToInt32($Data, 0)
                    $Sid = New-Object System.Security.Principal.SecurityIdentifier ($Data, 4)

                    $NewAceParams = @{
                        Principal = $Sid 
                        AccessMask = $AccessMask 
                        AppliesTo = $_ | GetAppliesToMapping
                        OnlyApplyToThisContainer = $_ | GetAppliesToMapping -CheckForNoPropagateInherit
                    }
                    $Ace = New-AccessControlEntry @NewAceParams
                    
                    # There are a few things that still need fixing
                    $Ace | 
                        Add-Member -MemberType NoteProperty -Name AceType -Force -Value IntegrityLevel -PassThru |
                        Add-Member -MemberType NoteProperty -Name IsInherited -Force -Value ($_.IsInherited)

                    New-AdaptedAcl -Ace $Ace -AccessMaskEnum ([PowerShellAccessControl.NonAccessMaskEnums.SystemMandatoryLabelMask]) |
                        Add-Member -MemberType NoteProperty -Name DisplayName -Force -Value $PathInfo.DisplayName -PassThru |
                        Add-Member -MemberType NoteProperty -Name Path -Force -Value $PathInfo.Path -PassThru


                }

            # What happens when a MIL doesn't exist? Return null, or return default (which would be Medium, but I don't know about flags)
        }
    }
}

#.ExternalHelp PowerShellAccessControl.Help.xml
function Get-ADObjectAceGuid {
    [CmdletBinding(DefaultParameterSetName="SearchAllByName")]
    param(
        [Parameter(ParameterSetName="SearchAllByGuid", Mandatory=$true)]
        [guid] $Guid,
        [Parameter(ParameterSetName="ExtendedRight")]
        [switch] $ExtendedRight,
        [Parameter(ParameterSetName="ValidatedWrite")]
        [switch] $ValidatedWrite,
        [Parameter(ParameterSetName="Property")]
        [switch] $Property,
        [Parameter(ParameterSetName="PropertySet")]
        [switch] $PropertySet,
        [Parameter(ParameterSetName="ClassObject")]
        [switch] $ClassObject,
        [Parameter(ParameterSetName="SearchAllByName")]
        [Parameter(ParameterSetName="SearchAllByGuid")]
        [ValidateSet("ExtendedRight", "ValidatedWrite", "Property", "PropertySet", "ClassObject")]
        [string[]] $TypesToSearch
    )

    dynamicparam {

        # No dynamic param if Guid was supplied
        if ($PSCmdlet.ParameterSetName -eq "SearchAllByGuid") { return }

        # This creates the 'Name' parameter. If none of the switches are provided, the function will
        # search all of the different types
        $ParamName = "Name"
        $ParamAliases = @()

        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary
        $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

        $ParamAttributes = New-Object System.Management.Automation.ParameterAttribute
        $ParamAttributes.Mandatory = $true
        $ParamAttributes.Position = 0
        $AttribColl.Add($ParamAttributes)

        # Not sure if I'm going to change param name and add aliases, so this will check each time
        if ($ParamAliases) {
            $ParamAliasAttribute = New-Object System.Management.Automation.AliasAttribute $ParamAliases
            $AttribColl.Add($ParamAliasAttribute)
        }

        $ParamSetName = $PSCmdlet.ParameterSetName
        if ($ParamSetName -like "SearchAll*") {
            # ValidateSet attribute isn't needed, so don't do anything extra
        }
        else {
            # Searching AD for the different types of objects can be very expensive. For that reason,
            # script scope variables hold the different ValidateSet objects. Here we check to
            # see if the variable has been set for this type of object (depending on the switch). If
            # it hasn't, this code block will populate that variable. Then the ValidateSet object is
            # always added:
            
             
            $ValidateSetVariableName = "__${ParamSetName}ValidateSet"
            $ValidateSet = Get-Variable -Scope Script -Name $ValidateSetVariableName -ValueOnly -ErrorAction Stop

            if ($ValidateSet -eq $null) { 
                # Hasn't been populated, so populate it:
                Write-Verbose "Getting list of values for '$ParamSetName' ValidateSet attribute..."
                try {
                    $ValidateSet = New-Object System.Management.Automation.ValidateSetAttribute (ConvertGuidToName -Type $ParamSetName -ListAll | select -exp DisplayName)
                    Set-Variable -Scope Script -Name $ValidateSetVariableName -Value $ValidateSet
                }
                catch {
                    # Error looking up values
                    throw $_
                }
            }

            $AttribColl.Add($ValidateSet)
        }

        $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
            $ParamName,
            [string],
            $AttribColl #[System.Collections.ObjectModel.Collection[System.Attribute]] $ParamAttributes
        )
        $DynParamDictionary.Add($ParamName, $DynamicParameter)

        # Return the param dictionary
        $DynParamDictionary
    }

    process {
        # Get the dynamic param. Just get the first one in case someone slipped more than one in somehow
        $Name = $PSBoundParameters.Name | select -First 1
    
        if ($PSCmdlet.ParameterSetName -like "SearchAll*") {
            # We have to do some actual work. User didn't know (or didn't specify)
            # what the type was. If they had (using one of the switches), the work
            # would already be done. See the else block below.

            switch ($PSCmdlet.ParameterSetName) {
                "SearchAllByName" {
                    # Replace * with .* (unless a backtick preceeds it, which is how the user can tell the function that the regex needs an actual asterisk there)
                    $NameRegex = $Name | ModifySearchRegex

                    $FunctionName = "ConvertNameToGuid"
                    $FunctionParams = @{
                        Name = $NameRegex
                    }
                }

                "SearchAllByGuid" {
                    $FunctionName = "ConvertGuidToName"
                    $FunctionParams = @{
                        Guid = $Guid
                    }

                    # If empty GUID is supplied, simply exit w/o returing anything. Get-Ace will search
                    # for empty GUIDs if -ObjectAceType or -InheritedObjectAceType are supplied. Even thought
                    # the SB says to pass -EA SilentlyContinue to this function, errors seem to be caught if
                    # the function has to call Get-SD first (it works fine when an SD object is passed as the
                    # -InputObject
                    if ($Guid -eq [guid]::Empty) { return }
                }

                default {
                    throw "Unknown parameter set"
                }
            }
            # Since we don't know what the type is, search through them all:
            $PossibleObjects = foreach ($Type in "ValidatedWrite", "ExtendedRight", "PropertySet", "Property", "ClassObject") {
                if ($PSBoundParameters.ContainsKey("TypesToSearch") -and $TypesToSearch -notcontains $Type) {
                    continue
                }

                & $FunctionName @FunctionParams -Type $Type -ErrorAction SilentlyContinue
            }

            if ($PossibleObjects -eq $null) {
                $Enumerator = $FunctionParams.GetEnumerator() | select -first 1
                Write-Error ("Unable to find any objects with {0} '{1}'" -f $Enumerator.Name, $Enumerator.Value)
                return
            }
            else {
                $PossibleObjects
            }

        }
        else {
            # Because of the dynamic params, anything passed through $Name should
            # be a valid attribute/class:
            $Type = $PSCmdlet.ParameterSetName
            ConvertNameToGuid -Name "^$Name$" -Type $Type
        }
    }
}
