function Get-CimInstanceFromPath {
<#
.SYNOPSIS
Converts a WMI path into a CimInstance object.
.DESCRIPTION
Get-CimInstanceFromPath takes an absolute WMI path and creates a WMI query that
Get-CimInstance takes as an argument. If everything works properly, a CimInstance
object will be returned.
.EXAMPLE
$Bios = Get-WmiObject Win32_BIOS; Get-CimInstanceFromPath -Path $Bios.__PATH
.EXAMPLE
Get-WmiObject Win32_BIOS | Get-CimInstanceFromPath
.NOTES
The function currently only works with absolute paths. It can easily be modified
to work with relative paths, too.
#>
<#
This function allows CIM objects to be represented as a string (like the WMI __PATH property). For example,
if you pass a CIM object that the module can get a security descriptor for (like a __SystemSecurity instance),
the SD's path property will include this string so that an instance of the CIM object can be obtained again.

WMI cmdlets have this functionality built-in:
$Computer = gwmi Win32_ComputerSystem
[wmi] $Computer.__PATH    # Get WMI instance from path

This function was more usefule in v1.x of this module before GetNamedSecurityInfo() and GetSecurityInfo()
windows APIs were used.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('__PATH')]
        # WMI path (Path must be absolute path, not relative path). See __PATH 
        # property on an object returned from Get-WmiObject
        [string] $Path
    )

    process {
        if ($Path -match "^\\\\(?<computername>[^\\]*)\\(?<namespace>[^:]*):(?<classname>[^=\.]*)(?<separator>\.|(=@))(?<keyvaluepairs>.*)?$") {
            $Query = "SELECT * FROM {0}" -f $matches.classname

            switch ($matches.separator) {

                "." {
                    # Key/value pairs are in string, so add a WHERE clause
                    $Query += " WHERE {0}" -f [string]::Join(" AND ", $matches.keyvaluepairs -split ",")
                }
            }

            $GcimParams = @{
                ComputerName = $matches.computername
                Namespace = $matches.namespace
                Query = $Query
                ErrorAction = "Stop"
            }

        }
        else {
            throw "Path not in expected format!"
        }

        Get-CimInstance @GcimParams
    }
}

function Get-CimPathFromInstance {
<#
The opposite of the Get-CimInstanceFromPath. This is how a __PATH property can be computed for a CIM instance.

Like the other function, this was more useful in 1.x versions of the module. It is still used in the GetWmiObjectInfo
helper function and the Get-Win32SecurityDescriptor exposed function.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true,ValueFromPipeline=$true)]
        [ciminstance] $InputObject
    )

    process {
        $Keys = $InputObject.CimClass.CimClassProperties | 
            Where-Object { $_.Qualifiers.Name -contains "Key" } |
            Select-Object Name, CimType | 
            Sort-Object Name

        $KeyValuePairs = $Keys | ForEach-Object { 

            $KeyName = $_.Name
            switch -regex ($_.CimType) {

                "Boolean|.Int\d+" {
                    # No quotes surrounding value:
                    $Value = $InputObject.$KeyName
                }

                "DateTime" {
                    # Conver to WMI datetime
                    $Value = '"{0}"' -f [System.Management.ManagementDateTimeConverter]::ToDmtfDateTime($InputObject.$KeyName)
                }

                "Reference" {
                    throw "CimInstance contains a key with type 'Reference'. This isn't currenlty supported (but can be added later)"
                }

                default {
                    # Treat it like a string and cross your fingers:
                    $Value = '"{0}"'  -f ($InputObject.$KeyName -replace "`"", "\`"")
                }
            }

            "{0}={1}" -f $KeyName, $Value
        }

        if ($KeyValuePairs) { 
            $KeyValuePairsString = ".{0}" -f ($KeyValuePairs -join ",")
        }
        else {
            # This is how WMI seems to handle paths with no keys
            $KeyValuePairsString = "=@" 
        }

        "\\{0}\{1}:{2}{3}" -f $InputObject.CimSystemProperties.ServerName, 
                               ($InputObject.CimSystemProperties.Namespace -replace "/","\"), 
                               $InputObject.CimSystemProperties.ClassName, 
                               $KeyValuePairsString


    }
}

function Convert-AclToString {
<#
    Converts an ACL into a string that has been formatted with Format-Table. The AccessToString and
    AuditToString properties on the PSObject returned from Get-SecurityDescriptor use this function.
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $Ace,
        [int] $MaxAces = 20,
        [PowerShellAccessControl.AppliesTo] $DefaultAppliesTo
    )

    begin {

        $TableProperties = @(
            @{ Label = "Type"
               Expression = { 
                   $CurrentAce = $_

                   if ($_.IsInherited) { $ExtraChar = ""}
                   else { $ExtraChar = "*" }

                   $ReturnString = switch ($_.AceType.ToString()) {
                       "AccessAllowed" { "Allow$ExtraChar" }
                       "AccessDenied" { "Deny$ExtraChar" }
                       "SystemAudit" {
                           $AuditSuccess = $AuditFailure = " "
                           if ($CurrentAce.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success) {
                               $AuditSuccess = "S"
                           }
                           if ($CurrentAce.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure) {
                               $AuditFailure = "F"
                           }

                           "Audit$ExtraChar {0}{1}" -f $AuditSuccess, $AuditFailure
                       }
                       default { $_ }

                   }

                   $ReturnString -join " "
               }
               Width = 9
             }
            @{ Label = "IdentityReference"
               Expression = { 
                   $_.Principal -replace "($env:COMPUTERNAME|BUILTIN|NT AUTHORITY)\\", ""
               }
               Width = 20
             }
            @{ Label = "Rights"
               Expression = { 
                $Display = $_.AccessMaskDisplay -replace "\s\(.*\)$"
                if (($PSBoundParameters.ContainsKey("DefaultAppliesTo") -and ($_.AppliesTo.value__ -ne $DefaultAppliesTo.value__)) -or ($_.OnlyApplyToThisContainer)) {
                    #$Display += " (Special)"
                    $Display = "Special"
                }
                $Display
               }
               Width = 20
             }
        )

        # If the following properties are the same, the ACEs will be grouped together
        $PropertiesToGroupBy = @(
            "AceType"
            "SecurityIdentifier"
            "StringPermissions"  # Modified form of the AccessMaskDisplay property, which is a string representation of the AccessMask (not grouping on that b/c GenericRights would mean that the AccessMasks might not match, while the effecitve rights do)
            "IsInherited"
            "OnlyApplyToThisContainer"
            "AuditFlags"         # Doesn't affect grouping access rights; this is a CommonAce property
            "ObjectAceType"           # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedObjectAceType"  # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
        )

        $CollectedAces = @()
        $ExtraMessage = $null
    }

    process {
        
        $CollectedAces += $Ace

        if ($CollectedAces.Count -ge $MaxAces) { 
            $ExtraMessage = "`n<...>"
            break 
        }

    }

    end {
        $Output = $CollectedAces | Format-Table -Property $TableProperties -HideTableHeaders -Wrap | Out-String | % { $_.Trim() }
        $Output = "{0}{1}" -f $Output, $ExtraMessage

        if (-not $Output) {
            "<ACL INFORMATION NOT PRESENT>"
        }
        else {
            $Output
        }
    }
}

function GetAppliesToMapping {
<#
    ACE inheritance and propagation are handled by the InheritanceFlags and PropagationFlags properties
    on an ACE. Based on the flags enabled, a GUI ACL editor will show you two separate pieces of information 
    about an ACE:
      1. Whether or not it applies to itself, child containers, and/or child objects
      2. Whether or not it applies only to direct children (one level deep) or all descendants (infinite
         depth)

    #1 is handled by both flags enumerations and #2 is only handled by PropagationFlags. This function
    provides a way for determining #1 and #2 if you provide the flags enumerations, and it also provides
    a way to get the proper flags enumerations for #1 if you provide string representations of where you
    would like the ACE to apply.
#>

    [CmdletBinding(DefaultParameterSetName='FromAppliesTo')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="FromAppliesTo", Position=0)]
        [PowerShellAccessControl.AppliesTo] $AppliesTo,
        [Parameter(Mandatory=$true, ParameterSetname="ToAppliesTo", ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.InheritanceFlags] $InheritanceFlags,
        [Parameter(Mandatory=$true, ParameterSetname="ToAppliesTo", ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.PropagationFlags] $PropagationFlags,
        [Parameter(ParameterSetname="ToAppliesTo")]
        [switch] $CheckForNoPropagateInherit,
        [Parameter(Mandatory=$true, ParameterSetName="ADFromAppliesTo")]
        [PowerShellAccessControl.AppliesTo] $ADAppliesTo,
        [Parameter(ParameterSetName="ADFromAppliesTo")]
        [switch] $OnlyApplyToThisADContainer = $false

    )

    begin {
        $Format = "{0},{1}"
        $AppliesToMapping = @{ # Numeric values from [PowershellAccessControl.AppliesTo] flags enum
            #ThisObjectOnly
            1 = $Format -f [System.Security.AccessControl.InheritanceFlags]::None.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildContainersOnly
            2 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__ 
            #ThisObjectAndChildContainers
            3 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ContainerInherit.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildObjectsOnly
            4 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__
            #ThisObjectAndChildObjects
            5 = $Format -f [System.Security.AccessControl.InheritanceFlags]::ObjectInherit.value__, [System.Security.AccessControl.PropagationFlags]::None.value__
            #ChildContainersAndChildObjectsOnly
            6 = $Format -f ([System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit").value__, [System.Security.AccessControl.PropagationFlags]::InheritOnly.value__ 
            #ThisObjectChildContainersAndChildObjects
            7 = $Format -f ([System.Security.AccessControl.InheritanceFlags] "ContainerInherit, ObjectInherit").value__, [System.Security.AccessControl.PropagationFlags]::None.value__
        }
    }

    process {
        switch ($PSCmdlet.ParameterSetName) {
            "FromAppliesTo" {
                $MappingString = $AppliesToMapping[$AppliesTo.value__]
                if ($MappingString -eq $null) { 
                    Write-Error ("Unable to map AppliesTo value ({0} to inheritance and propagation flags!" -f $AppliesTo) 
                    return
                }
                $Mappings = $MappingString -split ","

                New-Object PSObject -Property @{
                    InheritanceFlags = [System.Security.AccessControl.InheritanceFlags] $Mappings[0]
                    PropagationFlags = [System.Security.AccessControl.PropagationFlags] $Mappings[1]
                }
            }

            "ADFromAppliesTo" {
                $Format = "{0}, {1}"
                $ADAppliesToMapping = @{ # Numeric values from System.DirectoryServices.ActiveDirectorySecurityInheritance
                    # None is the same as [AppliesTo]::Object (doesn't matter if only applies here is set)
                    ($Format -f [PowerShellAccessControl.AppliesTo]::Object.value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    ($Format -f [PowerShellAccessControl.AppliesTo]::Object.value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None
                    # All is the same as [AppliesTo]::Object, ChildContainers and applies to only this container false
                    ($Format -f ([PowerShellAccessControl.AppliesTo] "Object, ChildContainers").value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
                    # SelfAndChildren is the same as [AppliesTo]::Object, ChildContainers and applies to only this container is true
                    ($Format -f ([PowerShellAccessControl.AppliesTo] "Object, ChildContainers").value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::SelfAndChildren
                    # Descendats is the same as [AppliesTo]::ChildContainers and applies to only this container false
                    ($Format -f [PowerShellAccessControl.AppliesTo]::ChildContainers.value__, $false) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents
                    # Children is the same as [AppliesTo]::ChildContainers and applies to only this container true
                    ($Format -f [PowerShellAccessControl.AppliesTo]::ChildContainers.value__, $true) = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Children
                }

                # Get numeric form of AppliesTo (get rid of ChildObjects if it is present)
                $AppliesToInt = $ADAppliesTo.value__ -band ([int32]::MaxValue -bxor [PowerShellAccessControl.AppliesTo]::ChildObjects)

                $AdSecurityInheritance = $ADAppliesToMapping[($Format -f $AppliesToInt, $OnlyApplyToThisADContainer)]

                if ($AdSecurityInheritance -eq $null) {
                    Write-Error ("Unable to convert AppliesTo ($ADAppliesTo) and OnlyApplyToThisContainer ($OnlyApplyToThisADContainer) to ActiveDirectorySecurityInheritance")
                    return
                }
                $AdSecurityInheritance
            }

            "ToAppliesTo" {
                if ($CheckForNoPropagateInherit) {
                    $PropagationFlags = $PropagationFlags.value__

                    # NoPropagateInherit doesn't deal with AppliesTo, so make sure that flags isn't active
                    if ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
                        $true
                    }
                    else {
                        $false
                    }

                }
                else {
                    # NoPropagateInherit doesn't deal with AppliesTo, so make sure that flag isn't active
                    if ($PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit) {
                        [System.Security.AccessControl.PropagationFlags] $PropagationFlags = $PropagationFlags -bxor [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit
                    }
                    $MappingString = $Format -f $InheritanceFlags.value__, $PropagationFlags.value__

                    $FlagsValue = $AppliesToMapping.Keys | where { $AppliesToMapping.$_ -eq $MappingString }
                    [PowerShellAccessControl.AppliesTo] $FlagsValue
                }
            }
        }
    }

}

function ConvertToSpecificAce {
<#
This function will take a CommonAce or ObjectAce and convert it into a .NET ACE that can be used
with security descriptors for Files, Folders, Registry keys, and AD objects. At some point, this
will probably be merged with ConvertToCommonAce to have a single function that looks at any type
of ACE coming in, and converts it to the right type based on the $AclType.

This function allows Add-AccessControlEntry and Remove-AccessControlEntry to work with SDs from
the native Get-Acl cmdlet.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        $Rules,
        [Parameter(Mandatory=$true)]
        # The type of the ACL that this ACE will belong to.
        [type] $AclType
    )

    begin {
        # Figure out what the final type of the rule should be. This depends on
        # the $AclType, and (if the ACL type is a CommonSecurityDescriptor), the
        # ACE itself

        if ($AclType.FullName -match "^(System\.Security\.AccessControl\.|System\.DirectoryServices\.)(\w+?)Security$") {
            # If its a File/DirectorySecurity create a FileSystemAccessRule (or Audit); otherwise, match can be used
            # as found (Registry or ActiveDirectory are all that I know of that will match this and work with New-Ace).
            $AclRuleKind = "{0}{1}{{0}}Rule" -f $Matches[1], ($Matches[2] -replace "^File|^Directory", "FileSystem")
            $AccessMaskParamName = $Matches[2] -replace "^Directory", "Folder"

            # This will leave a string with a {0} where Access or Audit will go later
        }
        elseif ($AclType.FullName -eq "System.Security.AccessControl.CommonSecurityDescriptor") {
# This isn't suppported until a future release:
throw ("{0} ACLs aren't supported" -f $AclType.FullName)
            # Final rule will need to either be a CommonAce or an ObjectAce (rules aren't different
            # b/w Access and Audit rules)

            # ObjectAce if .ObjectAceFlags exists and has flags other than 'None'
            # This is a design decision that may change. For non-AD ACEs, this is easy: .ObjectAceFlags
            # won't exist, so they will be converted to CommonAce objects (if they're not already). For
            # AD ACEs, though, either type is fine. ActiveDirectorySecurity objects always have .ObjectAceFlags
            # properties, even if the property is set to 'None'. This function would take one of those and
            # only output an ObjectAce if an ObjectAceType or InheritedObjectAceType were set.

            # Since more than one ACE can come through at once, this check is performed in the foreach()
            # section in the process block.
        }
        else {
            throw "Unknown ACL type ($($AclType.FullName))"
        }
    }

    process {

        foreach ($Rule in $Rules) {
            # See note in begin block for an explanation of this check:
            if ($AclType.Name -eq "CommonSecurityDescriptor") {
                if ($Rule.ObjectAceFlags -and $Rule.ObjectAceFlags -ne "None") {
                    $AclRuleKind = "System.Security.AccessControl.ObjectAce"
                }
                else {
                    $AclRuleKind = "System.Security.AccessControl.CommonAce"
                }
            }

            if ($Rule.AuditFlags -and $Rule.AuditFlags -ne [System.Security.AccessControl.AuditFlags]::None) {
                # This must be an audit rule
                $AuditOrAccess = "Audit"
            }
            else {
                # This must be an access rule
                $AuditOrAccess = "Access"
            }
            $CurrentRuleKind = $AclRuleKind -f $AuditOrAccess


            # Check to see if it's already the right type of rule
            if ($Rule.GetType().FullName -eq $CurrentRuleKind) {
                Write-Debug ("{0}: Rule already $CurrentRuleKind; no need to convert" -f $MyInvocation.InvocationName)
                $Rule
                continue
            }

            Write-Debug ("{0}: Rule is currently {1}; needs to be converted to {2}" -f $MyInvocation.InvocationName, $Rule.GetType().FullName, $CurrentRuleKind)

            # Make sure this is a known AceType (also, strip away 'Object' if it is at the end
            # of the type)
            if ($Rule.AceType -notmatch "^(\w+?)(Object)?$") {
                throw "Unknown ACE type ($($Rule.AceType))"
            }

            $CurrentAceType = $Matches[1]
            $NewAceParams = @{
                AceType = $CurrentAceType
                Principal = $Rule.SecurityIdentifier
                $AccessMaskParamName = $Rule.AccessMask
                AppliesTo = $Rule | GetAppliesToMapping
                OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
            }

            if ($Rule.ObjectAceType) {
                $NewAceParams.ObjectAceType = $Rule.ObjectAceType
            }

            if ($Rule.InheritedObjectAceType) {
                $NewAceParams.InheritedObjectAceType = $Rule.InheritedObjectAceType
            }

            if ($AuditOrAccess -eq "Audit") {
                # Convert flags to string, split on comma, trim trailing or leading spaces, and
                # create a boolean value to simulate [switch] statement for splatting:
                $Rule.AuditFlags.ToString() -split "," | ForEach-Object {
                    $NewAceParams.$("Audit{0}" -f $_.Trim()) = $true
                }
            }

            New-AccessControlEntry @NewAceParams -ErrorAction Stop
        }
    }
}

function ConvertToCommonAce {
<#
When dealing with the underlying CommonSecurityDescriptor object, ACEs need to be
CommonAce or ObjectAce types. This function takes lots of different types of ACEs
and converts them to ACEs that can be used by the CommonSecurityDescripor objects.

This allows the module to work with file system rules, registry rules, Win32_ACE rules,
etc.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ValueFromPipeline=$true)]
        [AllowNull()]
        [object[]] $Rules, # Allow any object to come through since we can accept different ACE types
        # By default, this will create an ACE that was not inherited, even if an inherited ACE is
        # passed to it. This switch will keep that (might actually flip the behavior at some point)
        #
        # One more thing: this won't do anything for a file or registry ACE, only an ACE from a
        # Win32SD or from an ACE in a RawAcl object
        [switch] $KeepInheritedFlag
    )

    process {
        foreach ($Rule in $Rules) {
            if ($Rule -eq $null) { continue }  # PSv2 iterates once if $Rules is null

            # We work with System.Security.AccessControl.CommonAce objects, so make sure whatever came in
            # is one of those, or can be converted to one:
            Write-Debug "$($MyInvocation.MyCommand): Type of rule is '$($Rule.GetType().FullName)'"
            switch ($Rule.GetType().FullName) {

                { $Rule.pstypenames -contains $__AdaptedAceTypeName } {

                    $IsRuleInherited = $Rule.IsInherited

                    # This is an ace created by the module; anything with this typename should be able to be
                    # piped directly to New-AccessControlEntry
                    # Note: Valid types should be CommonAce or ObjectAce

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Rule is adapted type; running original back through New-AccessControlEntry"
                    $Rule = $Rule | New-AccessControlEntry
                    break
                }

                { "System.Security.AccessControl.CommonAce", "System.Security.AccessControl.ObjectAce" -contains $_ } {
                    # Get a copy of the rule (we don't want to touch the original object)
                    Write-Debug "$($MyInvocation.MyCommand): No conversion necessary"
                    $Rule = $Rule.Copy()
                    $IsRuleInherited = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__)
                    break
                }

                { $_ -eq "System.Security.AccessControl.FileSystemAccessRule" -or 
                    $_ -eq "System.Security.AccessControl.RegistryAccessRule" -or
                  $_ -eq "System.DirectoryServices.ActiveDirectoryAccessRule" } {

                    # File system access rule or registry access rule

                    $IsRuleInherited = $Rule.IsInherited

                    if ($Rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                        $AceQualifier = [System.Security.AccessControl.AceQualifier]::AccessAllowed
                    }
                    else {
                        $AceQualifier = [System.Security.AccessControl.AceQualifier]::AccessDenied
                    }

                    $Params = @{
                        AceType = $AceQualifier
                        Principal = $Rule.IdentityReference
                        AppliesTo = $Rule | GetAppliesToMapping
                        OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
                        GenericAce = $true
                    }

                    if ($_ -eq "System.Security.AccessControl.FileSystemAccessRule") {
                        $Params.FileRights = $Rule.FileSystemRights
                    }
                    elseif ($_ -eq "System.Security.AccessControl.RegistryAccessRule") {
                        $Params.RegistryRights = $Rule.RegistryRights
                    }
                    else {
                        # AD access rule
                        $Params.ActiveDirectoryRights = [int] $Rule.ActiveDirectoryRights
                        $Params.ObjectAceType = $Rule.ObjectType
                        $Params.InheritedObjectAceType = $Rule.InheritedObjectType
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from access rule"
                    $Rule = New-AccessControlEntry @Params
                    break
                }

                { $_ -eq "System.Security.AccessControl.FileSystemAuditRule" -or 
                    $_ -eq "System.Security.AccessControl.RegistryAuditRule" -or 
                  $_ -eq "System.DirectoryServices.ActiveDirectoryAuditRule" } {

                    # File system or registry audit

                    $IsRuleInherited = $Rule.IsInherited

                    $Params = @{
                        Principal = $Rule.IdentityReference
                        AppliesTo = $Rule | GetAppliesToMapping
                        OnlyApplyToThisContainer = $Rule | GetAppliesToMapping -CheckForNoPropagateInherit
                        GenericAce = $true
                        AceType = [System.Security.AccessControl.AceQualifier]::SystemAudit
                        AuditSuccess = [bool] ($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)
                        AuditFailure = [bool] ($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Failure)
                    }

                    if ($_ -eq "System.Security.AccessControl.FileSystemAuditRule") {
                        $Params.FileSystemRights = $Rule.FileSystemRights
                    }
                    elseif ($_ -eq "System.Security.AccessControl.RegistryAuditRule") {
                        $Params.RegistryRights = $Rule.RegistryRights
                    }
                    else {
                        # AD audit rule
                        $Params.ActiveDirectoryRights = [int] $Rule.ActiveDirectoryRights
                        $Params.ObjectAceType = $Rule.ObjectType
                        $Params.InheritedObjectAceType = $Rule.InheritedObjectType
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from audit rule"
                    $Rule = New-AccessControlEntry @Params
                    break
                }

                { ($_ -eq "System.Management.ManagementBaseObject" -and
                   ($Rule.__CLASS -eq "Win32_ACE") -or ($Rule.__CLASS -eq "__ACE")) -or 
                  ($_ -eq "Microsoft.Management.Infrastructure.CimInstance" -and
                   ($Rule.CimClass.CimClassName -eq "Win32_ACE") -or ($Rule.CimClass.CimClassName -eq "__ACE")) } {

                    $IsRuleInherited = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__)

                    # Long and scary looking condition, but it just means do the
                    # following if it's a WMI object of the Win32_ACE class
                    
                    $Principal = ([System.Security.Principal.SecurityIdentifier] $Rule.Trustee.SIDString)

                    if ($Rule.AccessMask.GetType().FullName -eq "System.UInt32") {
                        # I've seen file access rights with UInts; convert them to signed ints:
                        $AccessMask = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($Rule.AccessMask), 0)
                    }
                    else {
                        $AccessMask = $Rule.AccessMask
                    }

                    # Common params b/w access and audit ACEs:
                    $Params = @{
                        Principal = $Principal
                        AccessMask = $AccessMask
                        AceFlags = $Rule.AceFlags
                        AceType = [System.Security.AccessControl.AceType] $Rule.AceType
                    }

                    if ($Rule.AceType -eq [System.Security.AccessControl.AceQualifier]::SystemAudit) {
                        # Not an access entry, but an audit entry
                        $Params.AuditSuccess = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::SuccessfulAccess.value__)
                        $Params.AuditFailure = [bool] ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::FailedAccess.value__)
                    }

                    # Make the rule:
                    Write-Debug "$($MyInvocation.MyCommand): Calling New-AccessControlEntry to create CommonAce from Win32_ACE"
                    $Rule = New-AccessControlEntry @Params
                    break

                }
                                    
                default {
                    Write-Error "Unknown access rule type!"
                    return
                }
            }

            if (-not $KeepInheritedFlag) {
                # There is a possibility that the ACE that came through
                # this function was inherited. If this function is being used,
                # it's usually to add or remove an ACE. In either of those 
                # scenarios, you don't want the resulting ACE to still be
                # inherited, so remove that flag if it's present
                if ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__) {
                    $Rule.AceFlags = [int] $Rule.AceFlags -bxor [System.Security.AccessControl.AceFlags]::Inherited.value__
                }
            }
            else {
                if ($IsRuleInherited -and (-not ([int] $Rule.AceFlags -band [System.Security.AccessControl.AceFlags]::Inherited.value__))) {
                    # If the original rule was inherited, but the converted one isn't, fix it!
                    $Rule.AceFlags = [int] $Rule.AceFlags -bxor [System.Security.AccessControl.AceFlags]::Inherited.value__
                }
            }

            # Output the rule:
            $Rule
        }
    }
}

function GetSecurityInfo {
<#
Wraps the PInvoke signature for GetNamedSecurityInfo and GetSecurityInfo. Path validation is up
to the caller (but this function should return a meaningful error message if an error is encountered)

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="Named")]
        [string] $Path,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="NotNamed")]
        [IntPtr] $Handle,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation = "Owner, Group, Dacl"
    )

    # Initialize pointers for the different sections (the only pointer we'll use is the one
    # to the entire SecurityDescriptor (it will work even if all sections weren't requested):
    $pOwner = $pGroup = $pDacl = $pSacl = $pSecurityDescriptor = [System.IntPtr]::Zero

    # Function and arguments are slightly different depending on param set:
    if ($PSCmdlet.ParameterSetName -eq "Named") {
        $FunctionName = "GetNamedSecurityInfo"
        $FirstArgument = $Path
    }
    else {
        $FunctionName = "GetSecurityInfo"
        $FirstArgument = $Handle
    }


    Write-Debug "$($MyInvocation.MyCommand): Getting security descriptor for '$FirstArgument' ($ObjectType) with the following sections: $SecurityInformation"

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
        # Make sure SeSecurityPrivilege is enabled, since this is required to view/modify
        # the SACL
        $AdjustPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
    }

    try {
        # Put arguments in array b/c PSv2 seems to require it to do the Invoke() call below (I didn't look
        # into it too much, but it was definitely erroring out when I had them in directly in the method
        # call):
        $Arguments = @(
            $FirstArgument,
            $ObjectType,
            $SecurityInformation,
            [ref] $pOwner, 
            [ref] $pGroup, 
            [ref] $pDacl,
            [ref] $pSacl,
            [ref] $pSecurityDescriptor
        )

        [PowerShellAccessControl.PInvoke.advapi32]::$FunctionName.Invoke($Arguments) | 
            CheckExitCode -ErrorAction Stop -Action "Getting security descriptor for '$FirstArgument'"


        if ($pSecurityDescriptor -eq [System.IntPtr]::Zero) {
            # I've seen this happen with ADMIN shares (\\.\c$); ReturnValue is 0,
            # but no SD is returned.
            #
            # Invalid pointer, so no need to try to free the memory
            Write-Error "No security descriptor available for '$FirstArgument'"
            return
        }

        try {
            # Get size of security descriptor:
            $SDSize = [PowerShellAccessControl.PInvoke.advapi32]::GetSecurityDescriptorLength($pSecurityDescriptor)
            Write-Debug "$($MyInvocation.MyCommand): SD size = $SDSize bytes"

            # Put binary SD in byte array:
            $ByteArray = New-Object byte[] $SDSize
            [System.Runtime.InteropServices.Marshal]::Copy($pSecurityDescriptor, $ByteArray, 0, $SDSize)

            # Output array:
            $ByteArray
        }
        catch {
            Write-Error $_
        }
        finally {
            # Clear memory from SD:
            Write-Debug "$($MyInvocation.MyCommand): Freeing SD memory"
            [PowerShellAccessControl.PInvoke.kernel32]::LocalFree($pSecurityDescriptor) | 
                CheckExitCode -Action "Freeing memory for security descriptor ($FirstArgument)"
        }
    }
    catch {
        Write-Error $_
    }
    finally {
        if ($AdjustPrivResults.PrivilegeChanged) {
            # Privilege was changed earlier, so now it must be reverted:

            $AdjustPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege -Disable

            if ($AdjustPrivResults.PrivilegeChanged -eq $false) {
                Write-Error "Error reverting SeSecurityPrivilege back to disabled!"
            }
        }
    }
}

function SetSecurityInfo {
<#
Wraps the PInvoke signature for SetNamedSecurityInfo and SetSecurityInfo. Path validation is up
to the caller (but this function should return a meaningful error message if an error is encountered)

#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="Named")]
        [string] $Path,
        [Parameter(Mandatory=$true, Position=0, ParameterSetName="NotNamed")]
        [IntPtr] $Handle,
        [Parameter(Mandatory=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [System.Security.Principal.IdentityReference] $Owner,
        [System.Security.Principal.IdentityReference] $Group,
        [System.Security.AccessControl.DiscretionaryAcl] $DiscretionaryAcl,
        [System.Security.AccessControl.SystemAcl] $SystemAcl,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation
    )

    if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
        # SecurityInformation enum wasn't provided, so function will
        # build it up using the sections that were provided
        $SecurityInformation = 0
    }

    # If SecurityInformation was specified, the following section may still modify it. Example would
    # be if SecurityInformation contained 'Dacl, ProtectedDacl' and the Owner parameter was supplied,
    # 'Owner' would be added to the SecurityInformation flag. The provided SecurityInformation will
    # be bor'ed with the flags for any of the four SD sections that are provided.

    # Get binary forms of sections:
    foreach ($SectionName in "Owner", "Group", "DiscretionaryAcl", "SystemAcl") {

        if ($PSBoundParameters.ContainsKey($SectionName)) {

            $Section = $PSBoundParameters.$SectionName

            $SectionLength = $Section.BinaryLength

            if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
                # SecurityInformation wasn't provided to function, so it's the function's
                # job to determine what needs to be set. It will do that by looking at the
                # sections that were passed

                # This will convert 'DiscretionaryAcl' to 'Dacl' and 'SystemAcl' to 'Sacl'
                # so that the section names will match with the SecurityInfo enum (Owner and
                # Group already match)
                $FlagName = $SectionName -replace "(ystem|iscretionary)A", "a"

                $SecurityInformation = $SecurityInformation -bor [PowerShellAccessControl.PInvoke.SecurityInformation]::$FlagName
            }

            if ($SectionLength -ne $null) {
                $ByteArray = New-Object byte[] $SectionLength
                $Section.GetBinaryForm($ByteArray, 0)
            }
            else {
                # In this scenario, a null section was passed, but the function was called
                # with this section enabled, so a null ACL will be applied
                $ByteArray = $null
            }
        }
        else {
            # Section wasn't specified, so no ptr
            $ByteArray = $null
        }

        Set-Variable -Scope Local -Name ${SectionName}ByteArray -Value $ByteArray -Confirm:$false -WhatIf:$false
    }

    # Function and arguments are slightly different depending on param set:
    if ($PSCmdlet.ParameterSetName -eq "Named") {
        $FunctionName = "SetNamedSecurityInfo"
        $FirstArgument = $Path
    }
    else {
        $FunctionName = "SetSecurityInfo"
        $FirstArgument = $Handle
    }

    Write-Debug "$($MyInvocation.MyCommand): Setting security descriptor for '$FirstArgument' ($ObjectType) with the following sections: $SecurityInformation"

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
        # Make sure SeSecurityPrivilege is enabled
        $SecurityPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
    }

    if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Owner) {
        # Attempt to grant SeTakeOwnershipPrivilege and SeRestorePrivilege. If privilege isn't held,
        # no error should be generated. That being said, these privs aren't always needed, so might
        # end up putting logic here (or in Set-SecurityDescriptor) that checks to see if the current
        # user has WRITE_OWNER and if the new owner is the current user (or a group that the current
        # user has the Owner attribute set), then no privs are necessary. Also, if the current user
        # doesn't have WRITE_OWNER, but they want the take ownership, then SeRestorePrivilege isn't
        # required. Just some stuff to think about...
        $TakeOwnershipPrivResults = SetTokenPrivilege -Privilege SeTakeOwnershipPrivilege
        $RestorePrivilegeResults = SetTokenPrivilege -Privilege SeRestorePrivilege
    }

    try {
        [PowerShellAccessControl.PInvoke.advapi32]::$FunctionName.Invoke(
            $FirstArgument,
            $ObjectType,
            $SecurityInformation,
            $OwnerByteArray, 
            $GroupByteArray, 
            $DiscretionaryAclByteArray,
            $SystemAclByteArray
        ) | CheckExitCode -ErrorAction Stop -Action "Setting security descriptor for '$FirstArgument'"
    }
    catch {
        Write-Error $_
    }
    finally {

        foreach ($PrivilegeResult in ($SecurityPrivResults, $TakeOwnershipPrivResults, $RestorePrivilegeResults)) {
            if ($PrivilegeResult.PrivilegeChanged) {
                # If this is true, then the privilege was changed, so it needs to be
                # reverted back. If it's false, then the privilege wasn't changed (either
                # b/c the user doesn't hold the privilege, or b/c it was already enabled;
                # it doesn't really matter why). So, disable it if it was successfully
                # enabled earlier.
    
                $NewResult = SetTokenPrivilege -Privilege $PrivilegeResult.PrivilegeName -Disable
                if (-not $NewResult.PrivilegeChanged) {
                    # This is an error; privilege wasn't changed back to original setting
                    Write-Error ("Error reverting {0}" -f $PrivilegeResult.PrivilegeName)
                }
            }
        }
    }
}

function GetWmiObjectInfo {
<#
Takes as input a WMI or CimInstance object. Returns as output an object with the following
properties: ClassName, ComputerName, Path, Namespace.

All of those properties are readily available for either type of object, but they are located
in different properties depending on the type of the object. This function returns a common,
known format for the properties that GetPathInformation can use.
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $WmiObject
    )

    process {
        $Properties = @{}
        switch -Wildcard ($WmiObject.GetType().FullName) {
            "Microsoft.Management.Infrastructure.CimInstance" {
                $Properties.ClassName = $WmiObject.CimSystemProperties.ClassName
                $Properties.ComputerName = $WmiObject.CimSystemProperties.ServerName
                $Properties.Path = $WmiObject | Get-CimPathFromInstance
                $Properties.Namespace = $WmiObject.CimSystemProperties.Namespace
            }
            "System.Management.Management*Object" {
                $Properties.ClassName = $WmiObject.__CLASS
                $Properties.ComputerName = $WmiObject.__SERVER
                $Properties.Path = $WmiObject.__PATH
                $Properties.Namespace = $WmiObject.__NAMESPACE
            }
            default {
                throw "Unknown WMI object!"
            }
        }
        New-Object PSObject -Property $Properties
    }

}

function SetTokenPrivilege {

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [int] $ProcessId = $pid,
        [Parameter(Mandatory=$true)]
        [ValidateSet( # Taken from Lee Holmes' privilege script:
            "SeAssignPrimaryTokenPrivilege", "SeAuditPrivilege", "SeBackupPrivilege", "SeChangeNotifyPrivilege", 
            "SeCreateGlobalPrivilege", "SeCreatePagefilePrivilege", "SeCreatePermanentPrivilege", 
            "SeCreateSymbolicLinkPrivilege", "SeCreateTokenPrivilege", "SeDebugPrivilege", "SeEnableDelegationPrivilege", 
            "SeImpersonatePrivilege", "SeIncreaseBasePriorityPrivilege", "SeIncreaseQuotaPrivilege", 
            "SeIncreaseWorkingSetPrivilege", "SeLoadDriverPrivilege", "SeLockMemoryPrivilege", "SeMachineAccountPrivilege", 
            "SeManageVolumePrivilege", "SeProfileSingleProcessPrivilege", "SeRelabelPrivilege", "SeRemoteShutdownPrivilege",
            "SeRestorePrivilege", "SeSecurityPrivilege", "SeShutdownPrivilege", "SeSyncAgentPrivilege", 
            "SeSystemEnvironmentPrivilege", "SeSystemProfilePrivilege", "SeSystemtimePrivilege", "SeTakeOwnershipPrivilege", 
            "SeTcbPrivilege", "SeTimeZonePrivilege", "SeTrustedCredManAccessPrivilege", "SeUndockPrivilege", "SeUnsolicitedInputPrivilege"
        )]
        [string] $Privilege,
        [switch] $Disable
    )
    
    begin {
        $Advapi32 = [PowerShellAccessControl.PInvoke.advapi32]
        $Kernel32 = [PowerShellAccessControl.PInvoke.kernel32]
    }

    process {

        if ($Disable) {
            $Action = "disable"
        }
        else {
            $Action = "enable"
        }

        # Wrap the process handle in a HandleRef to make sure it isn't GC'd:
        $Process = Get-Process -Id $ProcessId
        $hRef = New-Object System.Runtime.InteropServices.HandleRef ($Process, $Process.Handle)

        try {
            # Open the process token:
            $Message = "Getting token handle for '{0}' process ({1})" -f $Process.Name, $Process.Id
            Write-Debug "$($MyInvocation.MyCommand): $Message"

            $TokenHandle = [System.IntPtr]::Zero
            $Advapi32::OpenProcessToken(
                $hRef, 
                [System.Security.Principal.TokenAccessLevels] "AdjustPrivileges, Query",
                [ref] $TokenHandle
            ) | CheckExitCode -Action $Message

            # Look up the LUID for the privilege
            $LUID = New-Object PowerShellAccessControl.PInvoke.advapi32+LUID
            $Advapi32::LookupPrivilegeValue(
                $null,  # SystemName param; null means local system
                $Privilege,
                [ref] $LUID
            ) | CheckExitCode -Action "Looking up ID for '$Privilege' privilege"


            $LuidAndAttributes = New-Object PowerShellAccessControl.PInvoke.advapi32+LUID_AND_ATTRIBUTES
            $LuidAndAttributes.Luid = $LUID

            if ($Disable) {
                $LuidAndAttributes.Attributes = [PowerShellAccessControl.PInvoke.advapi32+PrivilegeAttributes]::Disabled
            }
            else {
                $LuidAndAttributes.Attributes = [PowerShellAccessControl.PInvoke.advapi32+PrivilegeAttributes]::Enabled
            }

            # Initialize some arguments for AdjustTokenPrivileges call
            $TokenPrivileges = New-Object PowerShellAccessControl.PInvoke.advapi32+TOKEN_PRIVILEGES
            $TokenPrivileges.PrivilegeCount = 1
            $TokenPrivileges.Privileges = $LuidAndAttributes

            $PreviousState = New-Object PowerShellAccessControl.PInvoke.advapi32+TOKEN_PRIVILEGES
            $ReturnLength = 0

            $Message = "Setting '$Privilege' to ${Action}d"
            Write-Debug "$($MyInvocation.MyCommand): $Message"
        
            $Advapi32::AdjustTokenPrivileges(
                $TokenHandle,
                $false, # Disable all privileges
                [ref] $TokenPrivileges,  # NewState
                [System.Runtime.InteropServices.Marshal]::SizeOf($PreviousState),
                [ref] $PreviousState,    # PreviousState
                [ref] $ReturnLength
            ) | CheckExitCode -Action $Message -ErrorAction Stop
        }
        catch {
            Write-Error $_
        }
        finally {
            # Check out $PreviousState. If privilege was changed, PrivilegeCount will
            # be greater than 0 (for our PInvoke signature, 1 is the highest we'll ever
            # see; we can only change one at a time
            $PrivilegeChanged = [bool] $PreviousState.PrivilegeCount
            Write-Debug "$($MyInvocation.MyCommand): Privilege changed: $PrivilegeChanged"

            Write-Debug "$($MyInvocation.MyCommand): Closing token handle"
            $Kernel32::CloseHandle($TokenHandle) | CheckExitCode -Action "Error closing token handle: $_" -ErrorAction Stop
        }

        # Create a return object
        New-Object PSObject -Property @{
            PrivilegeName = $Privilege
            ReturnCode = $ReturnCode
            PreviousState = $PreviousState
            PrivilegeChanged = $PrivilegeChanged
        }
    }
}

function CheckExitCode {
<#
    Writes an error message if the provided code is non-zero.
#>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $ExitCode,
        [switch] $WriteWarnings,
        [switch] $VerboseSuccesses,
        $Action
    )

    process {

        # ExitCode needs to an Int32, but I didn't want to make that be all that the input
        # takes. For that reason, we convert UInt32s to Int32s
        if ($ExitCode -isnot [int]) {
            try { 
                $ExitCode = [int] $ExitCode
            }
            catch {
                try {
                    $ExitCode = [System.BitConverter]::ToInt32([System.BitConverter]::GetBytes($ExitCode), 0)
                }
                catch {
                    Write-Error ("Can't convert '{0}' to [int]" -f $ExitCode.GetType().FullName)
                    return
                }
            }
        }

        if ($Action) {
            $Action = "{0}: " -f $Action
        }
        else {
            $Action = $null
        }

        try {
            $ErrorMessage = "{0}{1}" -f $Action, ([System.ComponentModel.Win32Exception] $ExitCode).Message
        }
        catch {
            Write-Error $_
            return
        }

        if ($ExitCode) {
            $Params = @{
                Message = $ErrorMessage   
            }

            if ($WriteWarnings) {
                $CmdletToUse = "Write-Warning"
            }
            else {
                $CmdletToUse = "Write-Error"
                $Params.ErrorId = $ExitCode
            }

            & $CmdletToUse @Params
        }
        else {
            if ($VerboseSuccesses) {
                Write-Verbose $ErrorMessage
            }
        }
    }
}

function GetPathInformation {
<#
This is the function that (hopefully) allows the functions that get and set the security descriptors to know
all necessary information about the object the user is interested in. It should be able to tell if it's a
container (like a folder, registry key, WMI namespace, DS object, etc), if its a DS object, what access mask
enumeration to use, the SdPath (used by GetSecurityInfo and SetSecurityInfo), the Path (a friendlier version
of the path; might be a PsPath, might be a text form of a WMI or CIM object), DisplayName (usually the path,
but sometimes extra information is conveyed), the ObjectType (used by Get and SetSecurityInfo), etc.

It should be able to take as input path strings, actual objects (.NET objects, WMI/CIM objects, WsMan objects,
etc). The output should be able to be splatted into New-AdaptedSecurityDescriptor (you'll still need the SDDL
or binary forms of the security descriptor)
#>
    [CmdletBinding(DefaultParameterSetName='Path')]
    param(
        [Parameter(Mandatory=$true, ParameterSetName='InputObject', ValueFromPipeline=$true)]
        $InputObject,
        [Parameter(ParameterSetName='DirectPath', ValueFromPipelineByPropertyName=$true)]
        [Parameter(ParameterSetName='Path', Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        # Path that the Get-Item cmdlet can use to get an object.
        [string[]] $Path = ".",
        [Parameter(Mandatory=$true, ParameterSetName='LiteralPath', ValueFromPipelineByPropertyName=$true)]
        # Literal path taht the Get-Item cmdlet can use to get an object
        [string[]] $LiteralPath,
        [Parameter(ParameterSetName='DirectPath', ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [Parameter(ParameterSetName='DirectPath')]
        [switch] $IsContainer = $false,
        [Parameter(ValueFromRemainingArguments=$true)]
        $__RemainingArguments
    )

    begin {
        # The process block has two main steps:
        #   Step 1: Collect potential input objects into the $InputObject variable. If that parameter was
        #           passed, then the function gets to skip step #1
        #   Step 2: Go through each object in the $InputObject variable. If the pstypenames property
        #           contains the following string, the object will not be "inspected" as much. This was
        #           originally used for when the path and ObjectType were explicitly supplied (notice
        #           the 'DirectPath' parameter set name), but it is actually used some in step #1, too.
        $DirectPathObjectType = "PowerShellAccessControl.DirectPath"
    }

    process {

        # Step 1: Convert everything to objects (unless $InputObject was the parameter supplied). 
        #      1.1: If paths were provided instead of objects, try to use Resolve-Path to get the fully resolved path, and the 
        #           type of the object the path points to. If that works, add a custom object with whatever info we were able
        #           to obtain, and give it a type of $DirectPathObjectType.
        #      1.2: If Resolve-Path can't handle it (and it wasn't already a DirectPath), check to see if it's some sort of
        #           path that this module is aware of (the module uses WMI/CIM path information kind of like a drive; also LDAP://
        #           paths can be used, etc
        try {
            switch ($PSCmdlet.ParameterSetName) {
                <#
                    If a path is defined, this function will first attempt to use Resolve-Path to see if it is a path
                    to a file, folder, or registry key (resolve-path isn't used if the -ObjectType parameter was passed;
                    that's handled in the second switch condition). If it's not a file, folder, or registry key, an error
                    will be thrown, and the catch block will check to see if it's a path format that this module created...

                    NOTE: This function used to use Get-Item for Path and LiteralPath param sets, but that means that you
                          have to have read access in order for the function to return, and read access isn't always necessary
                          to get/change a security descriptor. Doing it this way means that there's no read access requirement.
                #>
                { $_ -eq "Path" -or $_ -eq "LiteralPath" } {
                    # Pass either the -Path or -LiteralPath param and its value (depends on param set name)
                    $ResolvePathParams = @{
                        $PSCmdlet.ParameterSetName = $PSBoundParameters[$PSCmdlet.ParameterSetName]
                        ErrorAction = "Stop"
                    }

                    # Notice that whether or not the object is a container is being stored in a property called PsIsContainer. That's
                    # to mimic the behavior that will occur if an object (FileInfo, DirectoryInfo, RegistryKey) is passed intead of
                    # a path that is inspected w/ Resolve-Path (or a direct path where the -IsContainer parameter determines whether
                    # or not the object is a container)

                    $InputObject = foreach ($CurrentPath in (Resolve-Path @ResolvePathParams)) {
                        $ReturnObjectProperties = @{}
                        switch ($CurrentPath.Provider) {

                            Microsoft.PowerShell.Core\FileSystem {
                                $ReturnObjectProperties.Path = $ReturnObjectProperties.DisplayName = $ReturnObjectProperties.SdPath = $CurrentPath.ProviderPath
                                $ReturnObjectProperties.ObjectType += [System.Security.AccessControl.ResourceType]::FileObject
                                try {
                                    $ReturnObjectProperties.PsIsContainer = [bool]([System.IO.File]::GetAttributes($CurrentPath.ProviderPath) -band [System.IO.FileAttributes]::Directory)
                                }
                                catch {
                                    # There was an error checking on this, so assume it's not a container:
                                    Write-Warning ("Couldn't determine if '{0}' is a file or directory; treating as a file" -f $CurrentPath.ProviderPath)
                                    $ReturnObjectProperties.PsIsContainer = $false
                                }
                            }

                            Microsoft.PowerShell.Core\Registry {
                                $ReturnObjectProperties.SdPath = $CurrentPath.ProviderPath -replace "^HKEY_(LOCAL_)?"
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                                $ReturnObjectProperties.PsIsContainer = $true
                                $ReturnObjectProperties.Path = $CurrentPath.Path
                                $ReturnObjectProperties.DisplayName = $CurrentPath.ProviderPath
                            }

                            Microsoft.ActiveDirectory.Management\ActiveDirectory {
                                # Path should be in the form of {qualifier}:\{dn}
                                # We want the dn, so use Split-Path to remove the qualifier (which
                                # could be something other than the default AD:\
                                $ReturnObjectProperties.SdPath = (Split-Path $CurrentPath.Path -NoQualifier) -replace "(^\\)?"
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                                $ReturnObjectProperties.Path = $ReturnObjectProperties.DisplayName = $CurrentPath.Path
                            }

                            { $_ -match "^PowerShellAccessControl" } {
                            
                                # Proxy Resolve-Path function can handle long paths (somewhat). Provider returned is either
                                # PowerShellAccessControlDirectory or PowerShellAccessControlFile
                                $ReturnObjectProperties.SdPath = "\\?\{0}" -f $CurrentPath.Path
                                $ReturnObjectProperties.DisplayName = $ReturnObjectProperties.Path = $CurrentPath.Path
                                $ReturnObjectProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $ReturnObjectProperties.PsIsContainer = $CurrentPath.Provider -match "Directory$"
                            }
                            
                            default {
                                throw ("Unknown path provider: $_")
                            }
                        }   
                        
                        $ReturnObject = New-Object PSObject -Property $ReturnObjectProperties
                        $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)  # Function will inspect object type later
                        $ReturnObject
                    }

                    if ($InputObject -eq $null) {
                        Write-Error ("Error resolving path: {0}" -f $PSBoundParameters[$PSCmdlet.ParameterSetName])
                    }
                }

                "DirectPath" {
                    $InputObject = foreach ($CurrentPath in $Path) {
                        $ReturnObject = New-Object PSObject -Property @{
                            SdPath = $CurrentPath
                            ObjectType = $ObjectType
                            PsIsContainer = $IsContainer
                        }

                        $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)
                        $ReturnObject
                    }

                }

                "InputObject" {
                    # No extra work needed
                }

                default {
                    # Shouldn't happen
                    Write-Error "Unknown parameter set name!"
                    return
                }
            }
        }
        catch {
            <#
                Three possibilities:
                  1. An invalid path was presented, in which case we should write the error, then exit this iteration of the
                     function
                  2. The path is specially crafted by this module:
                       - WMI object
                       - Service object
                       - Process object
                     In that case, the module should understand the string. If it doesn't, it will throw an error.
                  3. The path is an AD path. If the path is in the form LDAP://{distinguishedname}, then everything works
                     great. If it doesn't have the LDAP:// prefix, then things might not work so well. To try to handle 
                     that, I have a check to see if 'DC=' is somewhere in the path. If so, [adsi]::Exists() is called
                     to see if it appears to be a valid AD path. If so, the path is modified to start with LDAP so the
                     switch statement will craft an object that can be used to create the adapted SD.
            #>
            
            $Paths = $PSBoundParameters[$PSCmdlet.ParameterSetName]
            $OriginalError = $_
            $InputObject = @()
            foreach ($CurrentPath in $Paths) {
                try {
                    if ($CurrentPath -match "^(?!LDAP://).*DC=" -and [adsi]::Exists("LDAP://{0}" -f $CurrentPath)) {
                        $CurrentPath = "LDAP://$CurrentPath"
                    }
                }
                catch {
                    # Don't need to do anything here since the path didn't have to be for AD
                }

                try {
                    $Qualifier = (Split-Path $CurrentPath -Qualifier -ErrorAction Stop).TrimEnd(":")
                    $PathWithoutQualifier = (Split-Path $CurrentPath -NoQualifier -ErrorAction Stop).Trim()

                    switch ($Qualifier) {
                        "ManagementObject" {
                            $InputObject += [wmi] $PathWithoutQualifier
                        }
                        
                        "CimInstance" {
                            $InputObject += Get-CimInstanceFromPath $PathWithoutQualifier
                        }

                        "Service" {
                            if ($PathWithoutQualifier -notmatch "^\\\\(?<computer>.*)\\(?<service>.*)$") {
                                throw "catch me"
                            }

                            $InputObject += Get-Service -ComputerName $matches.computer -Name $matches.service
                        }

                        "Process" {
                            if ($PathWithoutQualifier -notmatch "\(PID (?<processid>\d+)\)$") {
                                throw "catch me"
                            }

                            $InputObject += Get-Process -Id $matches.processid
                        }

                        LDAP {
                            $ReturnObject = New-Object PSObject -Property @{
                                # Get rid of any leading slashes
                                SdPath = $PathWithoutQualifier -replace "^\/*"
                                ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                            }

                            $ReturnObject.pstypenames.Insert(0, $DirectPathObjectType)
                            $InputObject += $ReturnObject
                        }

                        default {
                            # Must not be in proper path format!
                            throw "Catch this below and write original error"
                        }
                    }
                }
                catch {
                    throw $OriginalError
                    continue
                }
            }            
        }

        # Step 2: Go through each $InputObject and assemble all known information about it. That might include inspecting
        #         the underlying object.
:ObjectLoop foreach ($Object in $InputObject) {
            if ($Object -eq $null) { continue} 

            $OutputProperties = @{
                # This is usually just disposed of by the calling function, but in some instances it's useful
                # information
                InputObject = $Object
            }

            # One of this functions most important jobs is figuring out if the supplied object is a
            # container, since the inheritance and propagation flags allowed on ACEs contained in
            # SDs depends on that. Here, we check to see if the object that was supplied to this function
            # contains the information. There are several types of objects where this check doesn't matter
            # because the IsContainer is going to be hard coded to true or false, but NTFS permissions
            # definitely need this check since the object could be a file or a folder.
            # Note that this property may exist b/c a FileInfo, DirectoryInfo, RegistryKey, etc object
            # was passed into this function, or it may have been added earlier in this function b/c
            # a path was passed.
            if ($Object.PSIsContainer -ne $null) {
                $OutputProperties.IsContainer = $Object.PSIsContainer
            }

            Write-Debug "$($MyInvocation.MyCommand): Current object type: $($Object.GetType().FullName)"
            switch ($Object.GetType().FullName) {
                { $_ -match "System\.(Security\.AccessControl|DirectoryServices)\.(\w+)Security" } {
                    # User has passed a native .NET SD into the calling function. As of v3.0, the module should
                    # be able to handle those SDs, so this function is going to call itself against the path
                    # contained in the SD, but it is also going to add the Sddl from the SD's Sddl property
                    # to the output. The calling function will know that it shouldn't look up the SD at
                    # that point. This is desireable b/c this means that Get-SecurityDescriptor can now call
                    # on this function and convert a live, in-memory SD into the SD format that this module
                    # uses. This opens up the ability for Get-Ace and Set-SD to work with native .NET SDs.

                    Write-Debug "$($MyInvocation.MyCommand): Security descriptor is native .NET class ($_). Creating temporary 'Adapted SD'..."
                    # First, get path information. This will fill in the DisplayName, Path, ObjectType, etc
                    if ($Object.Path) {
                        try {
                            $OutputProperties = GetPathInformation -Path $Object.Path -ErrorAction Stop

                            # If there was an issue (and no errors were written), $OutputProperties will be $null. That's
                            # bad, so throw an error and let the catch {} block handle it
                            if ($OutputProperties -eq $null) { throw "Unable to get path information for security descriptor" }
                        }
                        catch {
                            Write-Error "Error getting access control entries from .NET class '$_'"
                            continue ObjectLoop
                        }
                    }
                    else {
                        # Using AD module w/ ntSecurityDescriptor or msExchMailboxSecurityDescriptor properites 
                        # will return an object w/ an empty Path property. Not sure if there are other scenarios.

                        # Try to get all of the necessary information (ObjectType is biggest we need to know; if other
                        # information is missing later, it gets filled in):
                        $OutputProperties.DisplayName = "[UNKNOWN]"
                        Write-Debug "$($MyInvocation.MyCommand): No path information available; setting DisplayName to $($OutputProperties.DisplayName)"

                        switch ($_) {
                            System.Security.AccessControl.DirectorySecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $OutputProperties.IsContainer = $true
                            }

                            System.Security.AccessControl.FileSecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                                $OutputProperties.IsContainer = $false
                            }

                            System.DirectoryServices.ActiveDirectorySecurity {
                                $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                            }

                            default {
                                Write-Error "Unable to get path information for the security descriptor. Use New-AdaptedSecurityDescriptor to convert this into an adapted security descriptor."
                                continue ObjectLoop
                            }
                        }
                    }

                    # Give the display name something to show that this is just an in-memory SD
                    $OutputProperties.DisplayName = "{0} (Converted .NET SD)" -f $OutputProperties.DisplayName

                    # Add the SDDL of the current SD:
                    $OutputProperties.Sddl = $Object.Sddl
                }


                { $Object.pstypenames -eq $DirectPathObjectType } {
                    # Direct path means that the function shouldn't do any inspection on the object. Maybe
                    # the user is looking for Share permissions by supplying a path; if left up to the module
                    # to figure out what to do, it would see that path as a valid file path, and lookup NTFS
                    # permissions. If the user supplied the -ObjectType to Get-SD, then direct path mode
                    # goes into effect, and the module just accepts what the user told it. Another area where
                    # this is useful is paths too long for the .NET framework.
                    $OutputProperties.SdPath = $Object.SdPath
                    if ($Object.Path -eq $null) {
                        $OutputProperties.Path = $Object.SdPath
                    }
                    else {
                        $OutputProperties.Path = $Object.Path
                    }
                    $OutputProperties.ObjectType = $Object.ObjectType
                    if ($Object.DisplayName -eq $null) {
                        $OutputProperties.DisplayName = "{0} ({1})" -f $OutputProperties.SdPath, $OutputProperties.ObjectType
                    }
                    else {
                        $OutputProperties.DisplayName = $Object.DisplayName
                    }
                }

                { $_ -like "System.Management.Management*Object" -or
                  $_ -eq "Microsoft.Management.Infrastructure.CimInstance" } {

                    # WMI object; we might be able to work with this
                    # To find out, lets get some info from it:
                    $WmiInfo = GetWmiObjectInfo $Object

                    # Path that allows module to get a WMI object back
                    $OutputProperties.Path = "{0}: {1}" -f $Object.GetType().Name, $WmiInfo.Path

                    # And another switch :)
                    switch ($WmiInfo.ClassName) {

                        "Win32_Service" {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Service
                            $OutputProperties.DisplayName = "Service: {0}" -f $Object.DisplayName
                        }

                        { $_ -eq "Win32_Printer" -or $_ -eq "MSFT_Printer" } {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Printer
                            $OutputProperties.DisplayName = "Printer: {0}" -f $Object.Name
                        }

                        "__SystemSecurity" {
                            # This isn't handled by Get/Set SecurityInfo cmdlets (which use Win32 calls), but it is handled
                            # by the module. We're going to set the paths to a string that this function can later use to
                            # get the WMI object back
                            $OutputProperties.SdPath = $OutputProperties.Path = "{0}: {1}" -f $Object.GetType().Name, $WmiInfo.Path
                            $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                            $OutputProperties.DisplayName = "WMI Namespace: {0}" -f $WmiInfo.Namespace
                            $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.WmiNamespaceRights]
                            $OutputProperties.IsContainer = $true
                        }

                        { $_ -eq "Win32_LogicalShareSecuritySetting" -or $_ -eq "Win32_Share" -or $_ -eq "MSFT_SmbShare" } {
                            $OutputProperties.SdPath = "\\{0}\{1}" -f $WmiInfo.ComputerName, $Object.Name
                            $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::LMShare
                            $OutputProperties.DisplayName = "Share: {0}" -f $Object.Name
                        }

                        "Win32_Process" {
                            
                            GetPathInformation -InputObject (Get-Process -Id $Object.ProcessId)
                            continue ObjectLoop
                        }

                        { "__SecurityDescriptor", "Win32_SecurityDescriptor" -contains $_ } {
                            $OutputProperties.Path = $OutputProperties.DisplayName = "[Win32_SecurityDescriptor]"
                            $OutputProperties.Sddl = $InputObject | ConvertFrom-Win32SecurityDescriptor -Sddl | select -exp Sddl
                            $OutputProperties.IsContainer = $true # Assume always a container so that inheritance flags on containers aren't messed up
                            $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                        }

                        default {
                            Write-Error ("Unsupported WMI class: {0}" -f $_)
                            continue ObjectLoop
                        }
                    }
                }

                { $Object.pstypenames -contains "Microsoft.ActiveDirectory.Management.ADObject" } {
                    # AD object from ActiveDirectory module was passed
                    $OutputProperties.SdPath = $OutputProperties.Path = $OutputProperties.DisplayName = $Object.DistinguishedName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::DSObjectAll
                    $OutputProperties.DsObjectClass = $Object.ObjectClass
                }


                "Microsoft.Win32.RegistryKey" {
                    # GetNamedSecurityInfo API function needs registry hive in a different format
                    # than PS uses (http://msdn.microsoft.com/en-us/library/windows/desktop/aa379593%28v=vs.85%29.aspx)
                    if ($Object.Name -notmatch "^(?<hive>[^\\]+)\\(?<path>.*)$") {
                        throw ("Uknown registry path: {0}" -f $Object.Name)
                    }
                    $Hive = $matches.hive -replace "^HKEY_(LOCAL_)?", ""
                    $RegPath = $matches.path

                    # Valid hives: CLASSES_ROOT, CURRENT_USER, MACHINE, USERS
                    if (-not ("CURRENT_USER","MACHINE" -contains $Hive)) {
                        throw ("Unknown registry hive: $Hive")
                    }

                    # SdPath can start with \\<machinename> for remote machines (maybe in the future)
                    $OutputProperties.SdPath = "$Hive\{0}" -f $RegPath  # Path may contain {}
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::RegistryKey
                    $OutputProperties.Path = $Object.PsPath
                    $OutputProperties.DisplayName = $Object.ToString()
                }

                { "System.IO.DirectoryInfo",
                  "System.IO.FileInfo" -contains $_ } {
                    $OutputProperties.SdPath = $OutputProperties.Path = $Object.FullName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::FileObject
                }
                
                "Microsoft.WSMan.Management.WSManConfigLeafElement" {

                    # Still figuring out how to handle WSMan better, but for now, leaf elements with
                    # an SDDL property will work

                    if ($Object.Name -ne "SDDL") {
                        Write-Error ("'{0}' does not contain a security resource" -f $Object.PsPath)
                        return
                    }

                    $OutputProperties.SdPath = $OutputProperties.Path = $Object.PsPath
                    $OutputProperties.ObjectType = $__PowerShellAccessControlResourceTypeName
                    $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.WsManAccessRights]
                }

                "System.ServiceProcess.ServiceController" {
                    $OutputProperties.SdPath = "\\{0}\{1}" -f $Object.MachineName, $Object.ServiceName
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::Service
                    $OutputProperties.DisplayName = "Service: {0}" -f $Object.DisplayName
                    $OutputProperties.Path = "Service: {0}" -f $OutputProperties.SdPath
                }

                "System.Diagnostics.Process" {
                    $OutputProperties.DisplayName = $OutputProperties.Path = "Process: {0} (PID {1})" -f $Object.Name, $Object.Id
                    
                    if (-not $Object.Handle) {
                        Write-Error ("Can't access process handle for {0}" -f $OutputProperties.DisplayName)
                        return
                    }

                    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef ($Object, $Object.Handle)
                    $OutputProperties.Handle = $HandleRef
                    $OutputProperties.ObjectType = [System.Security.AccessControl.ResourceType]::KernelObject
                    $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ProcessAccessRights]
                }


                default {
                    <#
                        An unsupported object was presented. We can just end it here, or we can see if the object has a
                        .Path property (could even check for a LiteralPath property). This might be a bad idea, but we're
                        going to check it for a path property, and if it has one, we're going to return information as
                        if that's what was called (param binder won't bind the path property if an object was piped into
                        this function, or if the -InputObject was called)
                    #>

                    Write-Debug "$($MyInvocation.MyCommand): Unknown object. Checking for path property or string value..."
                    if ($Object.Path -ne $null) {
                        try {
                            GetPathInformation -Path $Object.Path -ErrorAction Stop
                        }
                        catch {
                            Write-Error $_
                        }
                    }
                    elseif ($Object.GetType().FullName -eq "System.String") {
                        try {
                            GetPathInformation -Path $Object
                        }
                        catch {
                            Write-Error $_
                        }
                    }
                    else {
                        Write-Error ("{0} type not supported!" -f $_)
                    }

                    return
                }
            }

            if (-not $OutputProperties.ContainsKey("DisplayName")) {
                $OutputProperties.DisplayName = $OutputProperties.Path
            }

            # Add AccessMask enumerations based on object type (this may have been done earlier when detecting
            # what type of object was sent. WMI namespaces and WSMAN nodes share the same ObjectType, so they
            # were defined earlier. Processes aren't the only kernel objects that could potentially be handled,
            # so those are taken care of above, too
            if ($OutputProperties.AccessMaskEnum -eq $null) {
                switch ($OutputProperties.ObjectType.ToString()) {
                    "FileObject" {
                        $OutputProperties.AccessMaskEnum = [System.Security.AccessControl.FileSystemRights]
                    }
                    "Service" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ServiceAccessRights]
                        $OutputProperties.IsContainer = $false # Service objects aren't containers (at least I don't think they are)
                    }
                    "Printer" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.PrinterRights]
                        $OutputProperties.IsContainer = $true # The GUI appears to allow container inherit/propagation flags
                    }
                    { $_ -eq "RegistryKey" -or $_ -eq "RegistryWow6432Key" } {
                        $OutputProperties.AccessMaskEnum = [System.Security.AccessControl.RegistryRights]
                        $OutputProperties.IsContainer = $true # Registry keys are containers
                    }
                    "LMShare" {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.LogicalShareRights]
                        $OutputProperties.IsContainer = $false # I don't think logical shares are containers
                    }
                    { $_ -like "DSObject*" } {
                        $OutputProperties.AccessMaskEnum = [PowerShellAccessControl.ActiveDirectoryRights]
                        $OutputProperties.IsContainer = $true  # Is this always the case??
                        $OutputProperties.IsDsObject = $true
                    }
                }
            }

            # If the IsContainer property hasn't been defined by this point, it will be $false b/c of default value

            if ($OutputProperties.ObjectType -like "DsObject*" -and $OutputProperties.DsObjectClass -eq $null) {
                # If this is for an AD object, and the ActiveDirectory module didn't provide the output, we need
                # to look up the object class (that's needed to help with the AppliesTo for InheritedObjectAceTypes)
                try {
                    $OutputProperties.DsObjectClass = ([adsi] ("LDAP://{0}" -f $OutputProperties.SdPath)).Properties.ObjectClass | select -last 1
                }
                catch {
                    Write-Warning ("Unable to determine object class for '{0}'" -f $OutputProperties.SdPath)
                    $OutputProperties.DsObjectClass = "Unknown"
                }
            }

            if ($OutputProperties.DsObjectClass) {
                $OutputProperties.DisplayName = "{0} ({1})" -f $OutputProperties.DisplayName, ($OutputProperties.DsObjectClass -join ", ")
            }

            # Return a hash table that can be splatted to other functions...
            $OutputProperties

        } # end foreach $Object in $InputObject
    }
}

function GetNewAceParams {
<#
The *-AccessControlEntry functions all share parameters with New-AccessControlEntry. In early versions of the module, I
knew that new parameters could/would be added, so I didn't want to explicitly define them on all of the functions (I'd
have to change every function each time a parameter change was made). For that reason, I use dynamic params on the other
functions. Some of the functions require changes to the Parameter() attributes, so the switches to this function can
handle that.

I may end up explicitly defining each of the param blocks now that the module has (hopefully) matured enough to where
constant parameter changes aren't necessary.
#>
    [CmdletBinding()]
    param(
        # This can actually be used for other function/cmdlet parameters
        [Parameter(ValueFromPipeline=$true)]
        $ParameterDictionary = (Get-Command New-AccessControlEntry -ArgumentList @("SystemAudit") | select -exp Parameters),
        # Used for Add-AccessControlEntry and Remove-AccessControlEntry (when looking for an exact ACE match)
        [switch] $ReplaceAllParameterSets,
        # Used for Get-AccessControlEntry and Remove-AccessControlEntry (when looking for loose ACE matching)
        [switch] $RemoveMandatoryAttribute,
        [switch] $ConvertTypesToArrays,
        [switch] $AllowAliases,
        [switch] $AllowPositionAttributes
    )

    begin {
        $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
            Get-Member -MemberType Properties | 
            Select-Object -ExpandProperty Name

        # We're going to make copies of param attributes later. You basically have to create a blank attrib,
        # then change the properties. Knowing the writable ones will be very useful:
        $__WritableParamAttributePropertyNames = New-Object System.Management.Automation.ParameterAttribute | 
            Get-Member -MemberType Property | 
            Where-Object { $_.Definition -match "{.*set;.*}$" } | 
            Select-Object -ExpandProperty Name

        if (-not $AllowPositionAttributes) {
            # For the purposes of this module, we want to strip away any positional parameters from dynamic params:
            $__WritableParamAttributePropertyNames = $__WritableParamAttributePropertyNames | where { $_ -ne "Position" }
        }

    }

    process {

        # Convert to object array and get rid of Common params:
        $Parameters = $ParameterDictionary.GetEnumerator() | Where-Object { $__CommonParameterNames -notcontains $_.Key }

        if ($ReplaceAllParameterSets) {
            # Get all parameter set names (we need to take any params that are in the __AllParameterSets from New-AccessControlEntry
            # and manually add them to all available paramsets so that the __AllParameterSets on the function with these dynamic params
            # won't have those params in the __AllParameterSets set):
            $__NewAceParameterSetNames = foreach ($Parameter in $Parameters) {
                # PSv3 would make this sooooo much easier! We're unpacking all of the parameter set names from ParameterAttribute
                # attributes:
                foreach ($ParamAttribute in ($Parameter.Value.Attributes | where { $_.TypeId.Name -eq "ParameterAttribute" })) {
                    $ParamAttribute.ParameterSetName
                }
            }

            # We're only interested in unique names, and we don't care about the __AllParameterSets name (it will be replaced
            # on all of the params)
            $__NewAceParameterSetNames = $__NewAceParameterSetNames | 
                where { $_ -ne [System.Management.Automation.ParameterAttribute]::AllParameterSets } | 
                select -Unique
        }


        # Create the dictionary that this scriptblock will return:
        $DynParamDictionary = New-Object System.Management.Automation.RuntimeDefinedParameterDictionary

        foreach ($Parameter in $Parameters) {

            $AttribColl = New-Object System.Collections.ObjectModel.Collection[System.Attribute]

            $Parameter.Value.Attributes | ForEach-Object {
                $CurrentAttribute = $_
                $AttributeTypeName = $_.TypeId.FullName

                switch ($AttributeTypeName) {
                    "System.Management.Automation.ArgumentTypeConverterAttribute" {
# Ignore this; can't create a new one;
# does it get auto generated?
                        return  # So blank param doesn't get added
                    }

                    "System.Management.Automation.AliasAttribute" {
#                        # Create a new alias attribute:
#                        $NewParamAttribute = New-Object $AttributeTypeName $CurrentAttribute.AliasNames
                        # Since this won't get changed, there shouldn't be problem using the reference to the original
                        if ($AllowAliases) {
                            $AttribColl.Add($CurrentAttribute)
                        }
                    }

                    "System.Management.Automation.ValidateSetAttribute" {
                        # Can't create a new one; will this work?
                        $NewParamAttribute = $CurrentAttribute
                $AttribColl.Add($NewParamAttribute)

                    }

                    "System.Management.Automation.ParameterAttribute" {

                        if ($ReplaceAllParameterSets -and $CurrentAttribute.ParameterSetName -eq [System.Management.Automation.ParameterAttribute]::AllParameterSets) {
                            $ParameterSets = $__NewAceParameterSetNames
                        }
                        else {
                            $ParameterSets = $CurrentAttribute.ParameterSetName
                        }

                        foreach ($ParamSetName in $ParameterSets) {

                            $NewParamAttribute = New-Object System.Management.Automation.ParameterAttribute
                        
                            foreach ($PropName in $__WritableParamAttributePropertyNames) {
                                if ($NewParamAttribute.$PropName -ne $CurrentAttribute.$PropName) {  
                                    # nulls cause an error if you assign them to some of the properties
                                    $NewParamAttribute.$PropName = $CurrentAttribute.$PropName
                                }
                            }

                            if ($RemoveMandatoryAttribute) {
                                $NewParamAttribute.Mandatory = $false
                            }
                            $NewParamAttribute.ParameterSetName = $ParamSetName

                            $AttribColl.Add($NewParamAttribute)
                        }
                    }

                    default {
                        # I think the type converter was what was giving me the problems. This can probably be
                        # where everything except the parameterattribute and the type converter go, and the attribute
                        # can be added to the collection untouched
                        Write-Warning "don't handle dynamic param copying for $AttributeTypeName"
                        return
                    }
                }

            }

            $CurrentType = $Parameter.Value.ParameterType
            $ParameterType = $CurrentType

            if ($ConvertTypesToArrays) {
                # Make sure that the param type is an array:

                if (($CurrentType -ne [switch]) -and (-not $CurrentType.IsArray)) {
                    # Might need to add more types to not attempt this on
                    $NewType = ("{0}[]" -f $CurrentType.FullName) -as [type]

                    if ($NewType) {
                        $ParameterType = $NewType
                    }
                }
            }

            $DynamicParameter = New-Object System.Management.Automation.RuntimeDefinedParameter (
                $Parameter.Key,
                $ParameterType,
                $AttribColl
            )
            $DynParamDictionary.Add($Parameter.Key, $DynamicParameter)
        }

        # Return the dynamic parameters
        $DynParamDictionary

    }

}

function GetAceString {
<#
-Confirm and -WhatIf params use this to get a friendly description for an ACE.

This needs to be changed to use New-AdaptedAcl or the function should be removed, and
any functions that depend on it can use New-AdaptedAcl
#>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Ace
    )

    process {
        # Get identity reference:
        $UnknownAccountString = "Unknown Account"
        if ($Ace.IdentityReference -ne $null) {
            $IdentityReference = $Ace.IdentityReference
        }
        elseif ($Ace.SecurityIdentifier -ne $null) {
            $IdentityReference = $Ace.SecurityIdentifier
        }
        else {
            $IdentityReference = $UnknownAccountString
        }

        if ($IdentityReference -is [System.Security.Principal.SecurityIdentifier]) {
            try {
                $IdentityReference = $IdentityReference.Translate([System.Security.Principal.NTAccount])
            }
            catch {
                $IdentityReference = "$UnknownAccountString ($IdentityReference)"
            }
        }

        # Get ACE type:
        if ($Ace.AceType -ne $null) {
            $AceType = $Ace.AceType
        }
        elseif ($Ace.AuditFlags -ne $null) {
            $AceType = [System.Security.AccessControl.AceType]::SystemAudit
        }
        else {
            # Last ditch effort:
            $PropertyName = $Ace | Get-Member -MemberType Property -Name *Type | select -First 1 -ExpandProperty Name
            $AceType = $Ace.$PropertyName
        }

        # Get access mask:
        if ($Ace.AccessMask) {
            $AccessMask = $Ace.AccessMask
        }
        else {
            # Last ditch effort:
            $PropertyName = $Ace | Get-Member -MemberType Property -Name *Rights | select -First 1 -ExpandProperty Name
            $AccessMask = $Ace.$PropertyName
        }

        # Return output:
        "{0} {1} {2}" -f $AceType, $IdentityReference, $AccessMask
    }
}

function InvokeCommonAclMethod {
<#
Used for RemoveAccessRule, RemoveAccessRuleSpecific, AddAccessRule, AddAuditRule on
the Get-SD objects.

No param validation, so make sure the caller knows what's going on.
#>
    [CmdletBinding()]
    param(
        $Rule,
        $Acl,
        $MethodName
    )

    process {

        if ($Acl -eq $null) {
            return
        }

        if ($Rule.GetType().FullName -ne "System.Security.AccessControl.CommonAce") {
            # We need a CommonAce object for this to work
            try {
                $Rule = $Rule | ConvertToCommonAce -ErrorAction Stop
            }
            catch {
                Write-Error $_
                return
            }
        }

        if ($Rule.AceType -match "AccessAllowed(Object)?") {
            $AceType = [System.Security.AccessControl.AccessControlType]::Allow
        }
        elseif ($Rule.AceType -match "AccessDenied(Object)?") {
            $AceType = [System.Security.AccessControl.AccessControlType]::Deny
        }
        elseif ($Rule.AceType -match "SystemAudit(Object)?") {
            $AceType = $Rule.AuditFlags   # Misnamed, but this will still work
        }
        else {
            Write-Error ("Unknown ACE type: {0}" -f $Rule.AceType)
            return
        }

        # The methods (and their overloads) all have the same
        # first five arguments:
        $Arguments = @(
            $AceType, 
            $Rule.SecurityIdentifier, 
            $Rule.AccessMask, 
            $Rule.InheritanceFlags, 
            $Rule.PropagationFlags
        )

        if ($Rule.AceType -match "Object$") {
            # Methods overloads for object ACEs have extra arguments:
            $Arguments += $Rule.ObjectAceFlags
            $Arguments += $Rule.ObjectAceType
            $Arguments += $Rule.InheritedObjectAceType
        }

        Write-Debug "Invoking $MethodName"
        $Acl.$MethodName.Invoke($Arguments)
    }
}

function CustomShouldProcess {
<#
Function that attempts to mimic $PsCmdlet.ShouldProcess(). There is a common scenario using this module
where I haven't figure out a way to get $PsCmdlet.ShouldProcess() to work propertly. Here it is:
  - Set-SecurityDescriptor has a confirm impact of 'High' so that it will always prompt before saving
    a security descriptor (unless, of course, the -Force or -Confirm:$false parameters are passed)
  - Add-Ace, Remove-Ace, Disable/Enable-AclInheritance, Set-Owner, etc, all have an -Apply and -PassThru
    parameter, and they can all take more than one object as input that need an SD modified. Those functions
    have a ConfirmImpact of 'Medium'
  - When you call one of those with more than one object w/o -Force or -Confirm:$false, and the -Apply parameter
    is specified (or implied b/c of input object type), Set-SecurityDescriptor causes a prompt (which is good).
    The problem is that a YesAll or NoAll selection at the prompt will not work (you'll be prompted every time).
    That's annoying when you have ten or so SDs to modify, but it becomes absolutely unworkable when you try to
    do tens or hundreds of SDs. I originally tried to get around this by having all SDs saved until the end {}
    block, but that creates a limit on the number of SDs you can handle (even if it would be very difficult to
    find that limit). Also, a single terminating error would mean that none of the SDs would be applied.

I'm probably just missing something when it comes to $PsCmdlet.ShouldProcess(), so for now, this function is
an attempt to handle the issue. I want Set-SecurityDescriptor to prompt, but I don't want the modfication functions
to prompt (unless they're trying to apply).
#>
    [CmdletBinding(SupportsShouldProcess=$true, ConfirmImpact="Medium")]
    param(
        [Parameter(Mandatory=$true)]
        [string] $Action,
        [Parameter(Mandatory=$true)]
        [string] $Target,
        [Parameter(Mandatory=$true)]
        [ref] $__DefaultReturn,
        [Parameter(Mandatory=$true)]
        [ref] $__CustomConfirmImpact
    )

    $Message = "Performing the operation `"{0}`" on target `"{1}`"." -f $Action, $Target

    if ($WhatIfPreference) {
        Write-Host "What if: $Message"
        return $false
    }
    elseif ($ConfirmPreference -eq "None") {
        # -Confirm was passed with $false
        return $true
    }
    elseif ($__CustomConfirmImpact.Value.value__ -ge $ConfirmPreference) {

        $YesChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&Yes",
            "Continue with only the next step of the operation."
        )
        $YesToAllChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "Yes to &All",
            "Continue with all the steps of the operation."
        )
        $NoChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&No",
            "Skip this operation and proceed with the next operation"
        )
        $NoToAllChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "No to A&ll",
            "Skip this operation and all subsequent operations."
        )
        $SuspendChoice = New-Object System.Management.Automation.Host.ChoiceDescription (
            "&Suspend",
            'Pause the current pipeline and return to the command prompt. Type "exit" to resume the pipeline'
        )

        $Choices = [System.Management.Automation.Host.ChoiceDescription[]] @(
            $YesChoice, 
            $YesToAllChoice,
            $NoChoice,
            $NoToAllChoice,
            $SuspendChoice
        )

        do {
            $Result = $Host.UI.PromptForChoice("Confirm", "Are you sure you want to perform this action?`n${Message}", $Choices, 0) 

            switch ($Result) {
                1 { 
                    # Yes to All 
                    $__CustomConfirmImpact.Value = [System.Management.Automation.ConfirmImpact]::None
                    $__DefaultReturn.Value = $true
                }
                { 0, 1 -contains $_ } { 
                    # One of the Yes answers
                    return $true 
                }
                3 { 
                    # No to All
                    $__CustomConfirmImpact.Value = [System.Management.Automation.ConfirmImpact]::None
                    $__DefaultReturn.Value = $false
                }

                { 2, 3 -contains $_ } {
                    # One of the No ansers
                    return $false
                }
                4 { $Host.EnterNestedPrompt() }
            }
        } while ($Result -ge 4) # Loop until one of the first 4 choices is made
    }
    else {
        return $__DefaultReturn.Value
    }
}

function GetSdString {
<#
Used to get a ShouldProcess action string of what an SD object contains
#>
    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $SDObject,
        [PowerShellAccessControl.PInvoke.SecurityInformation] $SecurityInformation
    )

    process {
        $OutputString = ""

        if (-not $PSBoundParameters.ContainsKey("SecurityInformation")) {
            # $SecurityInformation wasn't supplied, so assume all SD parts will be listed
            # (If an Audit section isn't present, that will be removed next)
            $SecurityInformation = [PowerShellAccessControl.PInvoke.SecurityInformation]::All

            if ($SDObject.SecurityDescriptor.ControlFlags -and (-not $SDObject.AuditPresent)) {
                # So, if there is a ControlFlags property (there wouldn't be on a Get-Acl object), and a 
                # SACL isn't present, make sure the $SecurityInformation doesn't say to look for it.

                $SecurityInformation = $SecurityInformation -bxor [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl
            }
        }

        if ($SDObject.DaclProtectionDirty -and ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation] "ProtectedDacl, UnprotectedDacl")) {
            $OutputString += "`n{0}`n" -f $SDObject.DaclProtectionDirty
        }
        if ($SDObject.SaclProtectionDirty -and ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation] "ProtectedSacl, UnprotectedSacl")) {
            $OutputString += "`n{0}`n" -f $SDObject.SaclProtectionDirty
        }

        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Owner) {
            $OutputString += "`nOwner: {0}`n" -f $SDObject.Owner
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Group) {
            $OutputString += "`nGroup: {0}`n" -f $SDObject.Group
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedDacl) {
            $OutputString += "`nDACL Inheritance: Disabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedDacl) {
            $OutputString += "`nDACL Inheritance: Enabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Dacl) {
            $OutputString += "`nDACL{1}:`n{0}`n" -f $SDObject.AccessToString, "$(if ($SDObject.DaclProtectionDirty) { ' (NOT ACCURATE UNTIL DESCRIPTOR APPLIED)' } else { '' })"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::ProtectedSacl) {
            $OutputString += "`nSACL Inheritance: Disabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::UnprotectedSacl) {
            $OutputString += "`nSACL Inheritance: Enabled`n"
        }
        if ($SecurityInformation -band [PowerShellAccessControl.PInvoke.SecurityInformation]::Sacl) {
            $OutputString += "`nSACL{1}:`n{0}`n" -f $SDObject.AuditToString, "$(if ($SDObject.SaclProtectionDirty) { ' (NOT ACCURATE UNTIL DESCRIPTOR APPLIED)' } else { '' })"
        }

        $OutputString
    }
}

function GetSchemaObject {
<# 
This uses an ADSI searcher to lookup DS class objects and properties. It's called once to get a list of all
of them. The function's output is a custom object with the guid, several name properties (the DisplayName
is what will be used in the hash table used for caching), the PropertySet GUID (if the object is an
attributeSchema and it belongs to a PropertySet).
#>
    [CmdletBinding()]
    param(
        [Alias('Class')]
        [ValidateSet("attributeSchema","classSchema")]
        [string[]] $ObjectClass = ("attributeSchema","classSchema"),
        [guid[]] $SchemaIdGuid,
        [string[]] $Name,
        [string[]] $AdminDisplayName,
        [string[]] $LdapDisplayName,
        [Alias('PropertySetGuid')]
        [guid[]] $AttributeSecurityGuid
    )

    Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $ObjectClass objects"

    $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name

    $Properties = echo Name, ObjectClass, SchemaIdGuid, LdapDisplayName, adminDisplayName, attributeSecurityGUID

    if (-not $PSBoundParameters.ContainsKey("ObjectClass")) {
        # If object class wasn't specified via parameters, add the default value so loop
        # below will add it to the filter
        $PSBoundParameters.Add("ObjectClass", $ObjectClass)
    }

    $FilterConditions = @()

    foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {
        # Ignore common params:
        if ($__CommonParameterNames -contains $Parameter.Key) { continue }
        
        $CurrentSegment = @()
        foreach ($Value in $Parameter.Value) {
            if ($Value -is [guid]) {
                # Guids need to be transformed into ldap filter format
                $Value = -join ($Value.ToByteArray() | foreach { "\{0:x2}" -f $_ })
            }

            $CurrentSegment += "({0}={1})" -f $Parameter.Key, $Value
        }

        if ($CurrentSegment.Count -gt 1) {
            $StringFormat = "(|{0})"
        }
        else {
            $StringFormat = "{0}"
        }

        $FilterConditions += $StringFormat -f (-join $CurrentSegment)
    }

    if ($FilterConditions.Count -gt 1) {
        $StringFormat = "(&{0})"
    }
    else {
        $StringFormat = "{0}"
    }

    $LdapFilter = $StringFormat -f (-join $FilterConditions)

    Write-Debug "$($MyInvocation.MyCommand): LdapFilter = $LdapFilter"

    # Create a DirectorySearcher object:
    $RootDSE = [adsi] "LDAP://RootDSE"
    $SchemaNamingContext = [adsi] ("LDAP://{0}" -f $RootDSE.schemaNamingContext.Value)

    $Searcher = New-Object adsisearcher ($SchemaNamingContext, $LdapFilter, $Properties)
    $Searcher.PageSize = 1000

    $FoundResult = $false
    try {
        foreach ($Result in $Searcher.FindAll()) {
            if ($null -eq $Result) {
                break
            }
            $FoundResult = $true

            $DisplayNameProp = "LdapDisplayName"
            #$DisplayNameProp = "AdminDisplayName"
<#
AdminDisplayName is prettier, but LdapDisplayName is required for ObjectClass property off of AD 
objects to be able to be looked up properly. Possible to make yet another hash table that keeps 
up with objects whose LdapDisplayName and AdminDisplayName don't match, and that can be checked 
if necessary...
#>

            if ($Result.Properties.Item($DisplayNameProp)) {
                $DisplayName = $Result.Properties.Item($DisplayNameProp)[0]
            }
            else {
                $DisplayName = $Result.Properties.Item("Name")[0]
            }

            $Props =  @{
                Name = $Result.Properties.Item("Name")[0]
                SchemaIdGuid = [guid] $Result.Properties.Item("SchemaIdGuid")[0]
                ObjectClass = $Result.Properties.Item("ObjectClass")[$Result.Properties.Item("ObjectClass").Count - 1]
                DisplayName = $DisplayName
                AdminDisplayName = $Result.Properties.Item("AdminDisplayName")[0]
                LdapDisplayName = $Result.Properties.Item("lDAPDisplayName")[0]
            }

            # Property, so it could belong to a propertyset
            if ($Props.ObjectClass -eq "attributeSchema") {
                try {
                    $Props.PropertySet = [guid] $Result.Properties.Item("attributeSecurityGUID")[0]
                }
                catch {
                    # Probably blank, so no propertyset
                }
            }

            New-Object PSObject -Property $Props
        }
        $Searcher.Dispose()
        $SchemaNamingContext.Dispose()
        $RootDSE.Dispose()
    }
    catch {
        throw $_
    }

    if (-not $FoundResult) {
        Write-Error "Couldn't find any schema objects that matched the search criteria"
    }
    Write-Debug "$($MyInvocation.MyCommand): Exiting function"

}

function GetExtendedRight {
<# 
Like GetSchemaObject, except it looks in the Extended-Rights configuration container. It will find ExtendedRights, ValidatedWrites,
and PropertySets. Just like that function, custom PSObjects are output, and the function that calls this function will save all objects
to a hash table for faster lookups
#>
    [CmdletBinding()]
    param(
        [guid[]] $AppliesTo,
        [guid[]] $RightsGuid,
        [string[]] $Name,
        [string[]] $DisplayName,
        [ValidateSet("Self", "ExtendedRight", "ReadProperty,WriteProperty")]
        [string[]] $ValidAccesses
    )

    Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $ValidAccesses"

    $__CommonParameterNames = [System.Runtime.Serialization.FormatterServices]::GetUninitializedObject([type] [System.Management.Automation.Internal.CommonParameters]) | 
        Get-Member -MemberType Properties | 
        Select-Object -ExpandProperty Name

    $Properties = echo appliesTo, rightsGuid, DisplayName, validAccesses, Name

    $FilterConditions = @()

    foreach ($Parameter in $PSBoundParameters.GetEnumerator()) {

        if ($__CommonParameterNames -contains $Parameter.Key) { continue }
        $CurrentSegment = @()
        foreach ($Value in $Parameter.Value) {
            if ($Parameter.Key -eq "ValidAccesses") {
                # Valid accesses gets special handling:
                $Value = ([PowerShellAccessControl.ActiveDirectoryRights]$Value).value__
            }
            $CurrentSegment += "({0}={1})" -f $Parameter.Key, $Value
        }

        if ($CurrentSegment.Count -gt 1) {
            $StringFormat = "(|{0})"
        }
        else {
            $StringFormat = "{0}"
        }

        $FilterConditions += $StringFormat -f (-join $CurrentSegment)
    }

    if ($FilterConditions.Count -eq 0) {
        $FilterConditions += "(name=*)"
    }

    if ($FilterConditions.Count -gt 1) {
        $StringFormat = "(&{0})"
    }
    else {
        $StringFormat = "{0}"
    }

    $LdapFilter = $StringFormat -f (-join $FilterConditions)

    Write-Debug "$($MyInvocation.MyCommand): LdapFilter = $LdapFilter"

    # Create a DirectorySearcher object:
    $RootDSE = [adsi] "LDAP://RootDSE"
    $ExtendedRights = [adsi] ("LDAP://CN=Extended-Rights,{0}" -f $RootDSE.ConfigurationNamingContext.Value)
    $Searcher = New-Object adsisearcher ($ExtendedRights, $LdapFilter, $Properties)
    $Searcher.PageSize = 1000

    $FoundResult = $false
    try {
        foreach ($Result in $Searcher.FindAll()) {
            if ($null -eq $Result) {
                break
            }
            $FoundResult = $true

            New-Object PSObject -Property @{
                DisplayName = $Result.Properties.Item("DisplayName")[0]
                Name = $Result.Properties.Item("Name")[0]
                RightsGuid = [guid] $Result.Properties.Item("RightsGuid")[0]
                ValidAccesses = $Result.Properties.Item("ValidAccesses")[0]
                appliesTo = [guid[]] ($Result.Properties.Item("appliesTo") | % { $_ })
            }
        }
        $Searcher.Dispose()
        $ExtendedRights.Dispose()
        $RootDSE.Dispose()
    }
    catch {
        throw $_
    }

    if (-not $FoundResult) {
        Write-Error "Couldn't find any extended rights that matched the search criteria"
    }

    Write-Debug "$($MyInvocation.MyCommand): Exiting function"
}

function ConvertGuidToName {
<#
Helper function that allows GUID to name translation, and also the ability to list all relevant
schema objects (ClassObjects, PropertySets, Properties, ValidatedWrites, ExtendedRights).

Get-ADObjectAce uses the -ListAll in the dynamicparam{} block when one of the switches is used.

This function is also responsible for populating the hash table(s) used for quick lookup. When the
function is called, the $Type param is used to determine which hash table(s) is checked. If the
table has no data, the GetSchemaObject and/or GetExtendedRights functions are called to populate
it.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="ListAll")]
        [switch] $ListAll,
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Lookup")]
        [guid] $Guid,
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "ValidatedWrite", 
            "ExtendedRight",
            "Property",
            "PropertySet",
            "ClassObject"
        )]
        [string] $Type,
        # Can be used to limit -ListAll results for extended rights
        [guid[]] $AppliesTo
    )

    begin {
#        Write-Debug "$($MyInvocation.MyCommand): Entering function; searching for $Type"

        # Grab the proper caching hash table:
        $HashTable = Get-Variable -Scope Script -Name "__Ds${Type}Table" -ValueOnly

        # Check to see if table has been populated. If not, populate it:
        if ($HashTable.Count -eq 0) {
            Write-Debug "$($MyInvocation.MyCommand): Populating $Type table..."
            Write-Progress -Activity "Populating $Type table" -Status "Progress:" -Id 1 -PercentComplete 50

            # Figure out the function and parameters to run:
            $Params = @{}
            switch ($Type) {
                { "ValidatedWrite","ExtendedRight","PropertySet" -contains $_ } {
                    $FunctionName = "GetExtendedRight"
                    $KeyPropertyName = "RightsGuid"
                    if ($PSBoundParameters.ContainsKey("AppliesTo")) {
                        $Params.AppliesTo = $AppliesTo
                    }
                }
                ValidatedWrite {
                    $Params.ValidAccesses = "Self"
                }

                ExtendedRight {
                    $Params.ValidAccesses = "ExtendedRight"
                }

                PropertySet {
                    $Params.ValidAccesses = "ReadProperty,WriteProperty"
                }

                { "Property","ClassObject" -contains $_ } {
                    $FunctionName = "GetSchemaObject"
                    $KeyPropertyName = "SchemaIdGuid"
                }

                ClassObject {
                    $Params.ObjectClass = "classSchema"
                }

                Property {
                    $Params.ObjectClass = "attributeSchema"
                }

                default {
                    throw "Unknown param set!"
                }
            }

            try {
                & $FunctionName @Params | ForEach-Object {
                    try {
                        $Value = $_.DisplayName -replace "\s","-"
                        $HashTable.Add($_.$KeyPropertyName, $Value)
                    }
                    catch {
                        Write-Warning ("Duplicate ${Type}: {0}" -f $_.$ValuePropertyName)
                    }

                    if ($_.PropertySet) {
                        $__DsPropertyToPropertySetTable.Add($_.$KeyPropertyName, $_.PropertySet)
                    }
                }
            }
            catch {
                throw $_
            }
            finally {
                Write-Progress -Activity Done -Status "Progress:" -Id 1 -Completed
            }
        }
        
    }
    process {
        switch ($PSCmdlet.ParameterSetName) {
            Lookup {

                if ($HashTable.ContainsKey($Guid)) {
                    New-Object PSObject -Property @{
                        Guid = $Guid
                        Name = $HashTable[$Guid]
                        Type = $Type
                    }
                }
                else {
                    Write-Error "Unknown ${Type} GUID: $Guid"
                }
            }

            ListAll {
                $HashTable.GetEnumerator() | select @{N="Guid"; E={$_.Key}}, @{N="DisplayName"; E={$_.Value}}, @{N="Type"; E={$Type}}
            }
        }

    }

    end {
#        Write-Debug "$($MyInvocation.MyCommand): Exiting function"
    }
}

function LookupPropertySet {
<#
If given a property, get the propertyset
If given a propertyset, get the properties

Return is an object where 'Name' property is a property GUID, and
'Value' property is a propertyset GUID

Hash table is populated at the same time the Property hash table is
populated (inside ConvertGuidToName function)

Function is used in Get-EffectiveAccess function when ObjectAceType
is used.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ParameterSetName="Property")]
        $Property,
        [Parameter(Mandatory=$true, ParameterSetName="PropertySet")]
        $PropertySet
    )

    # If property to propertyset table hasn't been populated, then populate it
    if ($__DsPropertyToPropertySetTable.Count -eq 0) {
        $null = ConvertGuidToName -ListAll -Type "Property"
    }

    switch ($PSCmdlet.ParameterSetName) {
        "Property" {
            # Filter on name
            $FilterProperty = "Name"
        }

        "PropertySet" {
            # Filter on value
            $FilterProperty = "Value"
        }

        default {
            return
        }
    }

    $InputValues = $PSBoundParameters.($PSCmdlet.ParameterSetName)

    foreach ($InputValue in $InputValues) {
        # Guid form is needed to do lookup from hash table
        if ($InputValue -is [PSObject] -and $InputValue.Guid -is [guid]) {
            $InputValue = $InputValue.Guid
        }

        try {
            # Attempt to convert to a GUID (since string GUID may have been passed):
            $InputValue = [guid] $InputValue
        }
        catch {
            # Conversion failed, so attempt lookup via Get-ADObjectAceGuid

            $InputValue = Get-ADObjectAceGuid -Name $InputValue -ErrorAction Stop -TypesToSearch $PSCmdlet.ParameterSetName | select -ExpandProperty Guid
        }


        $__DsPropertyToPropertySetTable.GetEnumerator() | where { $InputValue -contains $_.$FilterProperty }
    }
}    

function ConvertNameToGuid {
<#
Opposite of ConvertGuidToName. If caching hash tables haven't been populated when the function
is called, ConvertGuidToName is called to populate them.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="Lookup")]
        [string] $Name,
        [Parameter(Mandatory=$true)]
        [ValidateSet(
            "ValidatedWrite", 
            "ExtendedRight",
            "Property",
            "PropertySet",
            "ClassObject"
        )]
        [string] $Type
    )

    begin {
        # Grab the proper caching hash table:
        $HashTable = Get-Variable -Scope Script -Name "__Ds${Type}Table" -ValueOnly

        # Check to see if table has been populated. If not, populate it by calling the -ConvertGuidToName -ListAll and throwing the results
        # away (I don't think this should ever happen. This function should really only be called from the Get-SdObjectAceType and
        # Get-SdInheritedObjectAceType functions, and they would have already populated the hash tables by calling convertguidtoname.:
        if ($HashTable.Count -eq 0) {
            $null = ConvertGuidToName -ListAll -Type $Type
        }
    }
    process {
        $HashTable.GetEnumerator() | where { $_.Value -match $Name } | select @{N="Guid"; E={[guid] $_.Name }}, @{N="Name"; E={$_.Value}}, @{N="Type";E={$Type}}
    }
}

function GetPermissionString {
<#
Originally used to translate AD rights into friendly strings (Get-EffectiveAccess and
New-AdaptedAcl both had the need to do this, and I didn't want to implement the code
inside each function. I later decided to run all AccessMasks through this function
(it makes the Get-EffectiveAccess code easier to follow). For that reason (originally
for AD), the structure of the function is a little wacky (it basically assumes you're
going to have an ObjectAceType, and if you don't (which you never will for any non-AD
permissions), it still creates some objects assuming you're using AD perms. 
#>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Int32] $AccessMask,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [guid] $ObjectAceType,
        $AccessMaskEnumeration = [int],
        [switch] $ListEffectivePermissionMode,
        [switch] $DontTranslateGenericRights
    )

    begin {

        $GenericRightsMask = 0
        [enum]::GetNames([PowerShellAccessControl.GenericAceRights]) | % { $GenericRightsMask = $GenericRightsMask -bor [PowerShellAccessControl.GenericAceRights]::$_.value__ }

    }

    process {
        
        # Function works off of ObjectAceTypeObject(s). This is geared towards AD permissions,
        # but non-AD permissions will work, too. If an ObjectAceType GUID isn't specified, then
        # a single ObjectAceTypeObject will be created after the if/else
        $ObjectAceTypeObject = $null
        if ($ObjectAceType -eq $null -or $ObjectAceType -eq [guid]::Empty) {
            $ObjectAceTypeName = "All"
        }
        else {
            try {
                $ObjectAceTypeObject = (Get-ADObjectAceGuid -Guid $ObjectAceType -ErrorAction Stop)
            }
            catch {
                $ObjectAceTypeName = $ObjectAceType
            }
        }
        
        # ObjectAceType either wasn't specified, or it was a GUID that couldn't be translated. Either
        # way, there will be no Type associated with the ObjectAceTypeObject. If this is an AD permission,
        # the name will either be 'All' (because the GUID was empty or non-existent, or the unknown GUID
        # (because it couldn't be translated)
        if ($ObjectAceTypeObject -eq $null) {
            $ObjectAceTypeObject = New-Object PSObject -Property @{
                Name = $ObjectAceTypeName
                Type = $null
            }
        }

        $Output = @()
        $NontranslatedString = $null

        # Check to see if GenericRights are included in the AccessMask (this works even if there are object
        # specific rights mixed in with the generic rights)
        if ($AccessMask -band $GenericRightsMask) {
            $GenericAccessMask = $AccessMask -band $GenericRightsMask   # Remove any object specific rights
            $AccessMask = $AccessMask -band (-bnot $GenericRightsMask)   # Remove any generic rights

            $GenericAccessMaskDisplay = $GenericAccessMask -as [PowerShellAccessControl.GenericAceRights]
            if ($DontTranslateGenericRights -or (-not $__GenericRightsMapping.ContainsKey($AccessMaskEnumeration))) {
                $Output += $GenericAccessMaskDisplay -split ", "
            }
            elseif ($__GenericRightsMapping.ContainsKey($AccessMaskEnumeration)) {
                $NontranslatedString = ($GenericAccessMaskDisplay, (GetPermissionString -AccessMask $AccessMask -AccessMaskEnumeration $AccessMaskEnumeration) | where { $_ -ne "None" }) -join ", "

                foreach ($CurrentRight in ($GenericAccessMaskDisplay -split ", ")) {
                    $AccessMask = $AccessMask -bor $__GenericRightsMapping[$AccessMaskEnumeration].$CurrentRight
                }

            }
        }

        $Output += foreach ($CurrentObject in $ObjectAceTypeObject) {
            # If an ObjectAceType was specified, then the AccessMask needs to be limited depending on the type
            # of the GUID. If an ObjectAceType wasn't specified (or if it was, but Get-ADObjectAceGuid couldn't
            # translate it), then the default{} block will take over, which won't try to limit the AccessMask
            switch ($CurrentObject.Type) {

                ClassObject {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] "CreateChild, DeleteChild"
                }

                ExtendedRight {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::ExtendedRight
                }

                { "Property", "PropertySet" -contains $_ } {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights] "ReadProperty, WriteProperty"
                }
                                
                ValidatedWrite {
                    $LimitingPermissions = [PowerShellAccessControl.ActiveDirectoryRights]::Self
                }

                default {
                    try {
                        $LimitingPermissions = ([System.Enum]::GetValues($AccessMaskEnumeration) | select -Unique | sort { $_ -as $AccessMaskEnumeration } -Descending ) -join ", "
                    }
                    catch {
                        # $AccessMaskEnumeration probably wasn't an enum
                        $LimitingPermissions = $AccessMask
                    }
                }
            }

            if ($ListEffectivePermissionMode) {
                # Instead of a single limiting value, attempt to split the $LimitingPermissions into
                # multiple rights. Those strings will be converted back to ints since they are enumeration
                # names
                $LimitingPermissions = $LimitingPermissions -split ", "
            }

            foreach ($CurrentPermission in $LimitingPermissions) {
                if (($CurrentPermission -as $AccessMaskEnumeration) -ne $null) {
                    # Current permission string can be cast as the enumeration type, so band the provided
                    # AccessMask with the limiting permission. When the function isn't in 'ListEffectivePermissionMode',
                    # this is only useful for AD permissions (e.g., ObjectAceType is for a property, but the
                    # access mask is for 'FullControl'. The ACE would really only give Read/Write property
                    # permission, so this is where the rest of the FullControl rights would be removed.
                    # When the function is in 'ListEffectivePermissionMode', this is useful for all ACEs,
                    # since it will split the enumeration strings up and show which rights the provided
                    # AccessMask maps to
                    $ModifiedAccessMask = $AccessMask -band ($CurrentPermission -as $AccessMaskEnumeration)
                }
                else {
                    # Couldn't successfully cast to the enum type (which shouldn't happen). Basically, don't
                    # modify the access mask
                    $ModifiedAccessMask = $AccessMask
                }

                if ($ListEffectivePermissionMode) {
                    # The modified access mask listed above might not provide the permission specified by 
                    # $CurrentPermission. For that reason, always list the $CurrentPermission as the
                    # display access mask in this mode
                    $DisplayAccessMask = $CurrentPermission -as $AccessMaskEnumeration
                }
                else {
                    # Modified access mask will be translated to the display access mask
                    $DisplayAccessMask = $ModifiedAccessMask
                }

                # Recast the int value back into the enum string(s)
                $AccessString = $DisplayAccessMask -as $AccessMaskEnumeration

                if ($AccessMaskEnumeration -eq [PowerShellAccessControl.ActiveDirectoryRights]) {
                    # AD rights may be heavily modified, so there's some extra work to do
                    $ObjectName = $CurrentObject.Name
                    $ObjectType = $CurrentObject.Type

                    if ($CurrentObject.Type -eq $null) {
                        $AccessString = $AccessString -replace "Self", "Perform $ObjectName ValidatedWrite"
                        $AccessString = $AccessString -replace "ExtendedRight", "Perform $ObjectName ExtendedRight"
                        $AccessString = $AccessString -replace "\b(\w*)(Child|Property)\b", ('$1 {0} $2' -f $ObjectName)
                        $AccessString = $AccessString -replace "($ObjectName) Child", '$1 ChildObject'

                        if ($ObjectName -eq "All") {
                            $AccessString = $AccessString -replace "(ValidatedWrite|ExtendedRight|ChildObject)", '$1s'
                            $AccessString = $AccessString -replace ("({0}) Property" -f $CurrentObject.Name), '$1 Properties'
                        }
                        elseif ($ObjectName -as [guid]) {
                            # Valid Guid with $null Type means that this is some unknown ObjectAceType
                            $AccessString = $AccessString += " (Unknown ObjectAceType $ObjectName)"
                        }
                    }
                    else {
                        $AccessString = $AccessString -replace "Self|ExtendedRight", "Perform"
                        $AccessString = $AccessString -replace "Property|Child", ""
                        $AccessString = $AccessString -replace ",", " and"

                        $AccessString = "{0} {1} {2}" -f $AccessString, $ObjectName, $ObjectType
                    }
                }

                if ($ListEffectivePermissionMode) {
                    New-Object PSObject -Property @{
                        Allowed = [bool] ($ModifiedAccessMask -eq ($CurrentPermission -as $AccessMaskEnumeration))
                        Permission = $AccessString
                    }
                }
                elseif ($ModifiedAccessMask -ne 0) {
                    # Return the access string
                    $AccessString
                }
                
                # Nothing returned if modified access mask is 0 and not in ListEffectivePermissionMode
            }
        }

        if ($ListEffectivePermissionMode) {
            $Output
        }
        else {

            # Previous foreach() loop usually only runs once. There are some GUIDs that can be
            # interpreted as more than one type (bf9679c0-0de6-11d0-a285-00aa003049e2 is a
            # property and a validated write), so it might have run more than once. In that
            # scenario, there may be more than one string that was returned.
            if (-not $Output) { $Output = "None" }
            $Output = $Output -join ", "

            if ($NontranslatedString) {
                $Output = "$Output ($NontranslatedString)"
            }

            $Output
        }
    }
}

function New-AdaptedAcl {
<#
Takes as input either an adapted SD object (from New-AdaptedSecurityDescriptor) (-SDObject parameter), or a collection
of access control entries (-Ace and -AccessMaskEnum parameters).

Returns as output a collection of CommonAce or ObjectAce objects that have extra properties added.

There is currently one issue that needs to be fixed: the AceType may be wrong on each object that comes out. That happens
with ObjectAces and/or dynamic access control CallbackAces. The AceType is overwritten with either AccessAllowed, AccessDenied,
or SystemAudit. This happens so that the "adapted" ACE can be piped into New-AccessControlEntry, Add-AccessControlEntry,
Remove-AccessControlEntry, etc. I might try to just overwrite the ToString() method of the AceType in the future

By default, generic access rights are translated to object specific access rights. That behavior can be suppressed by using
the -DontTranlsateGenericRights switch.

If the -GetInheritanceSource switch is used, inheritance source information will be checked using P/Invoke.
#>

    # Default set to handle empty ACL coming through
    [CmdletBinding(DefaultParameterSetName="CommonAceObjects")]
    param(
        # Arrays of these *can* come through, but function doesn't handle that since it's a function
        # that should only be called internally
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="BySD")]
        [ValidateScript({
            $_.pstypenames -contains $__AdaptedSecurityDescriptorTypeName
        })]
        $SDObject,
        [Parameter(ParameterSetName="BySD")]
        # Include discretionary ACL in output
        [switch] $Dacl,
        [Parameter(ParameterSetName="BySD")]
        # Include system ACL (if present) in output
        [switch] $Sacl,
        [switch] $DontTranslateGenericRights,
        [Parameter(ParameterSetName="BySD")]
        [switch] $GetInheritanceSource,
        [Parameter(Mandatory=$true, ParameterSetName="ByACE")]
        # Useful when there's a single ACE that needs to be converted (should actually work on multiples. This paramset was made for Get-MandatoryIntegrityLevel
        $Ace,
        [Parameter(ParameterSetName="ByACE")]
        $AccessMaskEnum
    )

    process {
        $AceObjects = @()
        $InheritanceArray = @{}  # Used to keep track of inheritance information for each ACL
        $GetPrincipalParams = @{} # Used when doing SID translation (not populated when ByACE
                                  # paramset is used)

        switch ($PSCmdlet.ParameterSetName) {
            BySD {

                # SID translation will fall back on SdPath and ObjectType if the SID can't be
                # translated locally, so fill in the hash table if the following properties
                # are available:
                if ($SDObject.SdPath) {
                    $GetPrincipalParams.SdPath = $SDObject.SdPath
                }
                if ($SDObject.ObjectType) {
                    $GetPrincipalParams.ObjectType = $SDObject.ObjectType
                }

                $AccessMaskEnum = $SDObject.GetAccessMaskEnumeration()

                # If neither -Dacl or -Sacl switch is provided, assume that the DACL is what's
                # requested
                if ($Dacl -or (-not $Dacl -and -not $Sacl)) {
                    # Add the discretionary ACL to the 
                    $AceObjects += '$SDObject.SecurityDescriptor.DiscretionaryAcl'

                    if ($GetInheritanceSource) {
                        try {
                            $InheritanceArray.Access = $SDObject | Get-InheritanceSource -Dacl -ErrorAction Stop
                        }
                        catch {
                            $GetInheritanceSource = $false
                        }
                    }
                }

                if ($Sacl) {
                    $AceObjects += '$SDObject.SecurityDescriptor.SystemAcl'

                    if ($GetInheritanceSource) {
                        try {
                            $InheritanceArray.Audit = $SDObject | Get-InheritanceSource -Sacl -ErrorAction Stop
                        }
                        catch {
                            $GetInheritanceSource = $false
                        }
                    }
                }
            }

            ByACE {
                $AceObjects += '$Ace'
            }

            default {
                return
            }
        }

        if ($AccessMaskEnum -eq $null) {
            # Numeric AccessMasks are cast to this type via -as in several places, so a null variable
            # won't work. If one wasn't supplied, just make the type [int] so that the AccessMask
            # stays numeric
            $AccessMaskEnum = [int]
        }

        $LastAceType = $null  # Used to keep track of the current ACE number so that Inheritance information
        $AceNumber = 0        # can be matched up. These are only used when $GetInheritanceSource is specified,
                              # and they are reset when the ACE type changes from Access to Audit (so it is
                              # assumed that the ACEs will come through with like types, i.e., all the Access ACEs
                              # (Allow or Deny) followed by all the Audit ACEs. That should be a valid
                              # assumption based on how $AceObjects is created)

        & ([scriptblock]::Create($AceObjects -join "; ")) | Where-Object { $_ } | ForEach-Object {

            $CurrentAce = $_

            # Make sure the ACE is a supported type:
            if ("IntegrityLevel", "CentralAccessPolicy" -contains $CurrentAce.AceType) {
                # Special CustomAce types that other functions in this module have put in. These are OK to adapt,
                # so no need to exit out with an error
            }
            elseif ($CurrentAce.AceType -notmatch "^(Access(Allowed|Denied)|SystemAudit)(Callback)?(Object)?$") {
                Write-Warning ("{0} ace type not supported!" -f $CurrentAce.AceType)
                return  # Exit this iteration of ForEach-Object
            }

            # Hash table will contain properties that will get added to the CommonAce
            <#
                Biggest time wasters (sorted):
                  1. AccessMaskDisplay
                  2. Principal
                  3. AceType

                Those together take the time it takes to get an AD object to over a second (not taking anything else in this function into account)
            #>
            $AdaptedAceProps = @{
                DisplayName = $SDObject.DisplayName
                InheritanceString = $SDObject.InheritanceString
                Path = $SDObject.Path
                Principal = GetPrincipalString -IdentityReference $CurrentAce.SecurityIdentifier @GetPrincipalParams
                AccessMaskDisplay = $CurrentAce | GetPermissionString -AccessMaskEnumeration $AccessMaskEnum -DontTranslateGenericRights:$DontTranslateGenericRights
                AceType = $CurrentAce.AceType.ToString() -replace "(Callback)?(Object)?$"  # All we care about is whether or not ACE is for Allow, Deny or Audit
                AppliesTo = $CurrentAce | GetAppliesToMapping
                OnlyApplyToThisContainer = [bool] ($CurrentAce.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::NoPropagateInherit)
            }

            if ($GetInheritanceSource) {
                # If inheritance source was obtained, there are potentially two lists: one for DACL and one for SACL
                # These ACEs are being fed through the pipeline, so the $CurrentAceType and $AceNumber keep track
                # of where in the $InheritanceArray.$CurrentAceType we are:
                $CurrentAceType = $AdaptedAceProps.AceType -replace "(Allowed$|Denied$|^System)"

                if ($LastAceType -ne $CurrentAceType) {
                    $AceNumber = 0
                    $LastAceType = $CurrentAceType
                }

                $AdaptedAceProps.InheritedFrom =  $InheritanceArray.$CurrentAceType[$AceNumber].AncestorName -replace "^\\\\\?\\"
            }

            # Make sure InheritedFrom property contains something:
            if (-not $AdaptedAceProps.InheritedFrom) {
                if ($CurrentAce.IsInherited) {
                    $AdaptedAceProps.InheritedFrom = "Parent Object"
                }
                else {
                    $AdaptedAceProps.InheritedFrom = "<not inherited>"
                }
            }

            # Clear this out in case a previous ACE was an object ACE, so later AD permission check won't show that old info:
            $InheritedObjectAceTypeProperties = $null

            # Do more stuff for ObjectAce
            if ($CurrentAce.AceType -match "Object$") {

                if ($CurrentAce.ObjectAceFlags -band [System.Security.AccessControl.ObjectAceFlags]::InheritedObjectAceTypePresent) {
                    try {
                        $InheritedObjectAceTypeProperties = ConvertGuidToName -Guid $CurrentAce.InheritedObjectAceType -Type ClassObject -ErrorAction Stop
                    }
                    catch {
                        $InheritedObjectAceTypeProperties = New-Object PSObject -Property @{
                            Name = $CurrentAce.InheritedObjectAceType
                            Type = $null
                            Guid = $CurrentAce.InheritedObjectAceType
                        }
                    }
                }

                $AdaptedAceProps.InheritedObjectAceTypeDisplayName = $InheritedObjectAceTypeProperties.Name
            }

            if ($CurrentAce.AceType -match "Callback") {
                $AdaptedAceProps.AccessMaskDisplay += " (CONDITIONAL STATEMENT GOES HERE)"
                $AdaptedAceProps.ConditonalBinaryData = $CurrentAce.GetOpaque()
                # Still missing a function to convert binary data to a string
            }

            # v3 and higher can take the hash table as a parameter to Add-Member, but to stay v2 compliant,
            # we'll just loop through each element in the ht and add it to the object to be returned. Also 
            # add the type name so the formatting system will take over how to display the objects.
            $AdaptedAceProps.GetEnumerator() | ForEach-Object {
                $CurrentAce | Add-Member -MemberType NoteProperty -Name $_.Name -Value $_.Value -Force
            }

            $CurrentAce.pstypenames.Insert(0, $__AdaptedAceTypeName)  #Custom typename used for PS formatting and type systems

            # Output ACE object:
            $CurrentAce

            # Increment ACE number to keep up with Inheritance information
            $AceNumber++
        }
    }
}

function MergeAclEntries {
<#
Use Get-Acl to take a look at c:\windows and HKLM:\SOFTWARE. You'll find multiple entries
for different principals. The access masks are defintely different b/c the ACEs that apply
to children are using generic rights. If you translate those generic rights into specific
rights, you'll have a situation (at least on some of the ACEs) where the access mask, principal,
inheritance source, etc all match. The only things that won't match are the AppliesTo. If all
those other properties match, you can do what the ACL editor GUI does, and only show one ACE
instead of multiple ones (and go ahead and combine the AppliesTo).

One downside to this: this makes the resulting ACE's InheritanceFlags, PropagationFlags, and/or
AceFlags not necessarily accurate. That's OK as long as you don't try to use the ACEs directly
on a RawSecurityDescriptor or CommonSecurityDescriptor object outside of the module (you can
use the .NET methods on one of the SD objects from this module, or the *-AccessControlEntry
functions just fine). This will work fine as long as you use the ACE(s) with the PAC module
b/c the ACE will be piped to the New-AccessControlEntry, and if the AppliesTo flags are specified
(which they will be if they're piped in), inheritance and propagation are taken from that property
instead of AceFlags property).

One case this function doesn't currently handle: If everything is the same except the AccessMask, e.g.,
two ACEs share everything, including the AppliesTo, then we should be able to combine the AccessMasks
and return a single ACE. That's pretty rare, and it'll just have to wait for a future release.
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $Ace
    )

    begin {
        $PropertiesToGroupBy = @(
            "AceType"
            "SecurityIdentifier"
            {$_.AccessMaskDisplay -replace "\s\(.*\)$" }  # Get rid of any parenthesis from Generic rights translations
            "IsInherited"
            "OnlyApplyToThisContainer"
            "AuditFlags"         # Doesn't affect grouping access rights; this is a CommonAce property
            "ObjectAceType"           # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedObjectAceType"  # Since it will be null if this is an ACE that doesn't contain this property, shouldn't affect grouping of normal non-object ACEs
            "InheritedFrom" 
        )

        $CollectedAces = @()
    }

    process {
        # Function needs to collect all input first
        $CollectedAces += $Ace
    }

    end {
        Write-Debug "$($MyInvocation.MyCommand): Starting to merge ACEs"

        # Group on the collected ACEs, then output them
        $CollectedAces | Group-Object $PropertiesToGroupBy -Debug:$false |
            # Most of the time, each group is going to have one item (which means no ACEs were grouped). When ACEs were grouped,
            # the AppliesTo properties will almost certainly be different. Also, it's possible for the AccessMasks to be different
            # (if one of the ACEs used generic rights that were translated in the __Permissions string, and the other used
            # object specific/standard rights, then the AccessMask could be different). For that reason, those two properites will
            # be combined from all objects in the group, and then the first item in the group will have those two properties updated,
            # and they will be sent out into the world:
            ForEach-Object {
                if ($_.Count -gt 1) {

                    $NewAppliesTo = $NewAccessMask = 0
                    $NewAccessMaskDisplay = @()

                    $_.Group | ForEach-Object -Process { 
                        $NewAppliesTo = $NewAppliesTo -bor $_.AppliesTo.value__ 
                        $NewAccessMask = $NewAccessMask -bor $_.AccessMask
                        $NewAccessMaskDisplay += ($_.AccessMaskDisplay -replace "\s\(.*\)$") -split ", "
                    }

                    $_.Group[0] | 
                        Add-Member -MemberType NoteProperty -Name AppliesTo -Force -PassThru -Value ($NewAppliesTo -as [PowerShellAccessControl.AppliesTo]) |
                        Add-Member -MemberType NoteProperty -Name AccessMask -Force -PassThru -Value $NewAccessMask |
                        Add-Member -MemberType NoteProperty -Name AccessMaskDisplay -Force -PassThru -Value (($NewAccessMaskDisplay | select -Unique) -join ", ")
                }
                else {
                    # Just output the only element:
                    $_.Group[0]
                }
            }
    }
}

function Get-InheritanceSource {
<#
Uses WinApi to get ACE inheritance source
#>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
        $SDObject,
        [switch] $Dacl,
        [switch] $Sacl
    )

    begin {
        # If neither switch was passed, act like Dacl was:
        if (-not ($PSBoundParameters.ContainsKey("Dacl") -or $PSBoundParameters.ContainsKey("Sacl"))) {
            $PSBoundParameters.Add("Dacl", $true)
        }

        # Each InheritArray entry takes up this much space (used to determine memory allocation, and to walk
        # the pointer
        $EntrySize = [System.Runtime.InteropServices.Marshal]::SizeOf([type][PowerShellAccessControl.PInvoke.InheritArray])
    }

    process {
        foreach ($AclType in "Dacl","Sacl") {
            if (-not $PSBoundParameters.$AclType) {
                continue
            }

            if ($AclType -eq "Dacl") {
                $Acl = $SDObject.SecurityDescriptor.DiscretionaryAcl
            }
            else {
                $Acl = $SDObject.SecurityDescriptor.SystemAcl
            }

            if ($null -eq $Acl) {
                Write-Debug "$AclType is null"
                continue
            }

            # Get binary ACL form:
            $AclBytes = New-Object byte[] $Acl.BinaryLength
            $Acl.GetBinaryForm($AclBytes, 0)

            if ($__GenericRightsMapping.ContainsKey($SDObject.GetAccessMaskEnumeration())) {
                $GenericMapping = $__GenericRightsMapping[$SDObject.GetAccessMaskEnumeration()]
            }
            else {
                Write-Error "Missing generic mapping for type [$($SDObject.GetAccessMaskEnumeration().FullName)]"
                continue
            }

            [guid[]] $GuidArray = @()
            if ($SDObject.DsObjectClass) {
                # This is an AD object, so we need the guid for the call to GetInheritanceSource
                [guid[]] $GuidArray = Get-ADObjectAceGuid -Name ("^{0}$" -f $SDObject.DsObjectClass) -TypesToSearch ClassObject | select -first 1 -exp Guid
            }

            Write-Debug  ("{0}: Calling GetInheritanceSource() for $AclType on {1}" -f $MyInvocation.MyCommand, $SDObject.DisplayName)
            try {
                # Allocate memory for the InheritArray return array (one for each ACE)
                $InheritArray = [System.Runtime.InteropServices.Marshal]::AllocHGlobal($Acl.Count * $EntrySize)

                if ($AclType -eq "Sacl") {
                    # Make sure SeSecurityPrivilege is enabled
                    $SecurityPrivResults = SetTokenPrivilege -Privilege SeSecurityPrivilege
                }
                else {
                    $SecurityPrivResults = $null
                }

                [PowerShellAccessControl.PInvoke.advapi32]::GetInheritanceSource(
                    $SDObject.SdPath,       # ObjectName
                    $SDObject.ObjectType,   # ObjectType
                    [PowerShellAccessControl.PInvoke.SecurityInformation]::$AclType, # SecurityInfo
                    $SDObject.SecurityDescriptor.IsContainer, # Container
                    [ref] $GuidArray,  # ObjectClassGuids
                    $GuidArray.Count,                      # GuidCount
                    $AclBytes,              # Acl
                    [System.IntPtr]::Zero,  # pfnArray (must be null)
                    [ref] $GenericMapping,        # GenericMapping
                    $InheritArray           # InheritArray (return)

                ) | CheckExitCode -Action "Getting $AclType inheritance source for '$($SDObject.SdPath)'" -ErrorAction Stop

                try {
                    $Ptr = $InheritArray.ToInt64()
                    for ($i = 0; $i -lt $Acl.Count; $i++) {

                        $Struct = [System.Runtime.InteropServices.Marshal]::PtrToStructure($Ptr, [type] [PowerShellAccessControl.PInvoke.InheritArray])
                        $Ptr += $EntrySize

                        New-Object PSObject -Property @{
                            AceNumber = $i
                            GenerationGap = $Struct.GenerationGap
                            AncestorName = $Struct.AncestorName
                        }
                    }
                }
                catch {
                    Write-Error $_
                    continue
                }
                finally {
                    # Make sure InheritArray is freed:
                    [PowerShellAccessControl.PInvoke.advapi32]::FreeInheritedFromArray(
                        $InheritArray, 
                        $Acl.Count, 
                        [System.IntPtr]::Zero
                    ) | CheckExitCode -Action "Freeing InheritedFrom array" -ErrorAction Stop
                }
            }
            catch {
                Write-Error $_
                continue
            }
            finally {
                # Free allocated memory
                [System.Runtime.InteropServices.Marshal]::FreeHGlobal($InheritArray)

                if ($SecurityPrivResults.PrivilegeChanged) {
                    # If this is true, then the privilege was changed, so it needs to be
                    # reverted back. If it's false, then the privilege wasn't changed (either
                    # b/c the user doesn't hold the privilege, or b/c it was already enabled;
                    # it doesn't really matter why). So, disable it if it was successfully
                    # enabled earlier.
                    $ActionText = "Reverting privilege '{0}' (back to disabled)" -f $SecurityPrivResults.PrivilegeName
                    Write-Debug "$($MyInvocation.MyCommand): $ActionText"
    
                    $NewResult = SetTokenPrivilege -Privilege $SecurityPrivResults.PrivilegeName -Disable
                    if (-not $NewResult.PrivilegeChanged) {
                        # This is an error; privilege wasn't changed back to original setting
                        Write-Error $ActionText 
                    }
                }
            }
        }
    }
}

function ConvertToIdentityReference {
<#
    Attempts to convert an arbitrary object ($Principal) into a IdentityReference object. Optional 
    switch parameters allow return object to be returned as NTAccount or SecurityIdentifier objects. 
    It doesn't use the .NET .Translate() method since that doesn't appear to support remote 
    translation. Instead, it uses two functions from this module that use P/Invoke
#>

    [CmdletBinding(DefaultParameterSetName="__AllParameterSets")]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, Position=0)]
        $Principal,
        [Parameter(Mandatory=$true, ParameterSetName="ReturnSid")]
        [switch] $ReturnSid,
        [Parameter(Mandatory=$true, ParameterSetName="ReturnAccount")]
        [switch] $ReturnAccount,
        [switch] $DontVerifyNtAccount,
        [string] $ComputerName
    )

    process {
        # Convert $Principal to an IdentityReference (most of the time, this will probably be a string, which will be treated
        # as a [System.Security.Principal.NTAccount], but can also be a SID object:

        $ExtraParam = @{}
        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $ExtraParam.ComputerName = $ComputerName
        }

        switch ($Principal.GetType().FullName) {
            { "System.String", "System.Security.Principal.NTAccount" -contains $_ } {
                # Principal will be an NTAccount (constructors below will cast this to an IdentityReference). Assume strings
                # are account names (if this fails, an attempt to convert to a sid will occur later)
                try {
                    $IdentityReference = [System.Security.Principal.NTAccount] $Principal
                }
                catch {
                    Write-Error $_
                    return
                }

                # Verify that this is a valid user
                try {
                    $TranslatedSid = Get-SidFromAccountName $IdentityReference @ExtraParam -ErrorAction Stop | select -exp Sid
                    $NtAccount = $IdentityReference  # Assign this if translation was successful
                }
                catch {
                    # Couldn't get a sid from what was assumed to be an account. It might have been a string representation of
                    # a SID, though
                    if ($Principal -like "S-*") { # This could use a regex
                        try {
                            # Attempt to convert supplied string to a SID (this shouldn't happen much with PAC module, b/c
                            # SIDs will usually come through as an object, not a string
                            $TranslatedSid = $IdentityReference = [System.Security.Principal.SecurityIdentifier] $Principal

                            # If we made it here, conversion must have worked!
                            break  # Break out of switch statement
                        }
                        catch {
                            # Don't do anything; parent catch block will output error
                        }
                    }

                    if ($DontVerifyNtAccount) {
                        $NtAccount = $IdentityReference  # Go ahead and assign this
                        break # Break out of switch statement
                    }
                    else {
                        # Write error and break out of process{} block
                        Write-Error $_
                        return
                    }
                }
            }

            default {
                try {
                    # The only type that should allow this would be a SecurityIdentifier. Attempt the cast,
                    # and write an error if it doesn't work.
                    $TranslatedSid = $IdentityReference = [System.Security.Principal.IdentityReference] $Principal
                }
                catch {
                    Write-Error $_
                    return
                }
            }
        }

        switch ($PSCmdlet.ParameterSetName) {
            ReturnSid {
                # If everything worked, this should have been populated (if it's null, there must have been an error
                # and -DontVerifyNtAccount switch was passed)
                $TranslatedSid
            }

            ReturnAccount {
                if ($NtAccount -eq $null) {
                    # This can happen if a SID was passed to the function. Go ahead and try to translate it:
                    try {
                        $Account = Get-AccountFromSid -Sid $TranslatedSid @ExtraParam -ErrorAction Stop
                        [System.Security.Principal.NTAccount] $NtAccount = ("{0}\{1}" -f $Account.Domain, $Account.AccountName).TrimStart("\")
                    }
                    catch {
                        Write-Error $_
                        return
                    }
                }
                $NtAccount
            }

            default {
                # Just return the identity reference
                $IdentityReference
            }
        }
    }
}

function GetPrincipalString {
<#
I may put this functionality in the ConvertToIdentityReference. This uses ConvertToIdentityReference to attempt to
convert an IdentityReference into a string. If the initial translation fails, the $SdPath and $ObjectType are
inspected, and ConvertToIdentityReference may be called again w/ a remote computer name. If that translation fails,
the original IdentityReference is returned along with an 'Account Unknown' string

It gets its own function b/c New-AdaptedAcl and the Onwer/Group properties all need the exact same functionality
(attempt local translation, then possibly remote translation)
#>

    param(
        [Parameter(Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias("SecurityIdentifier", "Principal")]
        $IdentityReference,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        [System.Security.AccessControl.ResourceType] $ObjectType,
        [Parameter(ValueFromPipelineByPropertyName=$true)]
        $SdPath
    )

    process {
        $Principal = $null

        # This will convert the SID to a string representation of the account. If translation isn't possible, principal name will be null (which
        # will make it easy to tell accounts that weren't able to be translated later)
        try {
            $Principal = $IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop
        }
        catch {
            # Error converting. Could this be a user/group on a remote system? Check the SdPath to see if we can pull a
            # machine name out of it

            try {
                if ($PSBoundParameters.ObjectType -match "^DSObject" -and $PSBoundParameters.SdPath -match "((,DC=[^,]*)*?)$") {
                    $DomainName = $matches[1] -replace ",DC=", "."
                    $DomainName = $DomainName -replace ".*DnsZones\."
                    $DomainName = $DomainName -replace "^\."

                    $Principal = "{0}\{1}" -f $DomainName, ($IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop -ComputerName $DomainName)


                }
                elseif ($PSBoundParameters.SdPath -match "^(\\\\|Microsoft\.WSMan\.Management\\WSMan::)(?<ComputerName>[^\\]+)\\") {
                    $Principal = "{0}" -f ($IdentityReference | ConvertToIdentityReference -ReturnAccount -ErrorAction Stop -ComputerName $matches.ComputerName)
                }
            }
            catch {
                # Don't do anything here. We'll take care of it outside of the if statement
            }

            if (-not $Principal) {
                # Couldn't convert SID, so return account unknown string. Overloading ToString() method b/c sometimes this value
                # may be used as an identity reference (e.g., Owner property couldn't be translated. If just string is returned,
                # then there will be an error trying to use the actual string value, but a SID object that can't be translated
                # could still be used successfully
                $Principal = $IdentityReference | Add-Member -PassThru -MemberType ScriptMethod -Name ToString -Force -Value { "Account Unknown ({0})" -f $this.Value }
            }
        }

        $Principal
    }
}

function Get-SidFromAccountName {

    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [string] $AccountName,
        # If Computer/Domain name is used above in [computer]\[user] above, this param will be used in place of the computer/domain above
        [string] $ComputerName
    )

    process {
        $Use = New-Object PowerShellAccessControl.PInvoke.advapi32+SID_NAME_USE
        $ByteArraySize = 0
        $DomainNameBufferLength = 0

        # Was a remote location specified through the parameters?
        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $Computer = $PSBoundParameters.ComputerName
        }
        else {
            $Computer = $null
        }

        # Dirty hack. ALL APPLICATION PACKAGES can't be converted from name to SID if the authority is included. Remove
        # that authority if found:
        $AccountName = $AccountName -replace "^APPLICATION PACKAGE AUTHORITY\\"

        try {
            # First call tells us SID and DomainName size; return code should be 122:
            $ReturnValue = [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $null, 
                [ref] $ByteArraySize, 
                $null, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            )
            $ReturnValue | CheckExitCode -Action "Looking up SID for '$AccountName'" -ErrorAction Stop
        }
        catch {
            #$RegEx = "^((?<ComputerOrDomain>[^\\]+)\\)?(?<AccountName>[^\\]+)$"
            # Previous RegEx would fail with things like 'DOMAIN\BUILTIN\Pre-Windows 2000 Compatible Access'
            $RegEx = "^((?<ComputerOrDomain>[^\\]+)\\)?(?<AccountName>.+)$"

            if (($ReturnValue -eq 1332) -and 
                ($AccountName -match $RegEx) -and 
                (-not $PSBoundParameters.ContainsKey("ComputerName"))
               ) {
                $null = $PSBoundParameters.Remove("AccountName")
                Write-Debug ("{0}: Failed to translate SID; attempting with computername '{1}'" -f $MyInvocation.MyCommand, $matches.ComputerOrDomain)
                Get-SidFromAccountName -AccountName $matches.AccountName -ComputerName $matches.ComputerOrDomain @PSBoundParameters
                return
            }
            elseif ($ReturnValue -ne 122) {
                Write-Error $_
                return
            }
        }
            
        $ByteArray = New-Object byte[] $ByteArraySize
        $DomainName = New-Object System.Text.StringBuilder $DomainNameBufferLength

        try {
            [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountName(
                $Computer, 
                $AccountName, 
                $ByteArray, 
                [ref] $ByteArraySize, 
                $DomainName, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            ) | CheckExitCode -ErrorAction Stop
        }
        catch {
            Write-Error $_
            return
        }

        New-Object PSObject -Property @{
            Use = $Use
            Domain = $DomainName.ToString()
            Sid = (New-Object System.Security.Principal.SecurityIdentifier ($ByteArray, 0))
        }
    }
}

function Get-AccountFromSid {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory=$true, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('SecurityIdentifier')]
        [System.Security.Principal.SecurityIdentifier] $Sid,
        [string] $ComputerName
    )

    process {

        $SidBytes = New-Object byte[] $Sid.BinaryLength
        $Sid.GetBinaryForm($SidBytes, 0)

        $Use = New-Object PowerShellAccessControl.PInvoke.advapi32+SID_NAME_USE
        $NameBufferLength = $DomainNameBufferLength = 255
        $Name = New-Object System.Text.StringBuilder $NameBufferLength
        $DomainName = New-Object System.Text.StringBuilder $DomainNameBufferLength

        if ($PSBoundParameters.ContainsKey("ComputerName")) {
            $Computer = $PSBoundParameters.ComputerName
        }
        else {
            $Computer = $null
        }

        try {
            [PowerShellAccessControl.PInvoke.advapi32]::LookupAccountSid(
                $Computer, 
                $SidBytes, 
                $Name, 
                [ref] $NameBufferLength, 
                $DomainName, 
                [ref] $DomainNameBufferLength, 
                [ref] $Use
            ) | CheckExitCode -ErrorAction Stop
        }
        catch {
            Write-Error "Error looking up account for SID '$Sid': $($_.Exception.Message)"
            return
        }

        New-Object PSObject -Property @{
            Use = $Use
            Domain = $DomainName.ToString()
            AccountName = $Name.ToString()
        }
    }
}

function Select-SingleObject {
<#
.SYNOPSIS
Takes multiple inputs and allows a user to choose a single one for the output.

.DESCRIPTION
This function will filter multiple inputs into a single output. If the PS version
is greater than version 3.0, Out-GridView is used by default. Otherwise, the
built-in prompt for choice is used.

If a specific prompt type is desired, that can be handled with -PromptMode 
parameter.
#>

    [CmdletBinding()]
    param(
        [Parameter(ValueFromPipeline=$true)]
        $InputObject,
        [ValidateSet("OutGridView","PromptForChoice")]
        $PromptMode,
        [string] $Title = "Please choose one",     # Title for out-gridview; description for prompt for choice
        [string] $PromptForChoiceTitle = "Choice",
        [int] $MaxObjectsToDisplay
    )

    begin {
        if ($PSBoundParameters.ContainsKey("PromptMode")) {
            $PromptMode = $PSBoundParameters.PromptMode
        }
        else {
            if ($PSVersionTable.PSVersion -ge "3.0") {
                $PromptMode = "OutGridView"
            }
            else {
                $PromptMode = "PromptForChoice"
            }
        }

        # Extra check to make sure OutGridView won't be used on a system w/o at least PSv3:
        if ($PromptMode -eq "OutGridView" -and ($PSVersionTable.PSVersion -lt "3.0")) {
            Write-Warning "OutGridView prompt mode not supported in this version of PowerShell"
            $PromptMode = "PromptForChoice"
        }

        $AllInputObjects = @()
    }

    process {
        foreach ($CurrentInputObject in $InputObject) {
            $AllInputObjects += $CurrentInputObject
        }
    }

    end {
        if ($AllInputObjects.Count -eq 0) {
            Write-Error "No objects were provided as input"
            return
        }
        elseif ($AllInputObjects.Count -eq 1) {
            # Single object came through, so output that object and exit
            $AllInputObjects | select -first 1
            return
        }

        # Use Select-Object along with some of the function's parameters to work
        # on the InputObject:
        $SelectObjectParams = @{}
        if ($PSBoundParameters.ContainsKey("MaxObjectsToDisplay")) {
            $SelectObjectParams.First = $MaxObjectsToDisplay
        }

        $AllInputObjects = $AllInputObjects | Select-Object @SelectObjectParams

        switch ($PromptMode) {
            OutGridView {
                do {
                    $AllInputObjects = $AllInputObjects | Out-GridView -Title $Title -OutputMode Single
                } while ($AllInputObjects.Count -gt 1)
                
                $Output = $AllInputObjects
            }

            PromptForChoice {
                $UsedHotkeys = @()

                # This is used as a backup in case the ToString() method doesn't return anything
                $PropertyNames = $AllInputObjects | select -first 1 @Property | Get-Member -MemberType Properties | select -First 4 -ExpandProperty Name
                [System.Management.Automation.Host.ChoiceDescription[]] $Choices = $AllInputObjects | ForEach-Object {
                    $Name = $_.ToString()
                    if (-not $Name) {
                        $Name = foreach ($CurrentPropertyName in $PropertyNames) {
                            $_.$CurrentPropertyName.ToString()
                        }
                        $Name = $Name -join " - "
                    }

                    for ($i = 0; $i -lt $Name.Length; $i++) {
                        $CurrentLetter = $Name[$i]
                        if ($UsedHotkeys -notcontains $CurrentLetter) {
                            $UsedHotkeys += $CurrentLetter
                            $Name = "{0}&{1}" -f $Name.SubString(0, $i), $Name.SubString($i, $Name.Length - $i)
                            break
                        }
                    }

                    New-Object System.Management.Automation.Host.ChoiceDescription $Name
                }

                $Result = $Host.UI.PromptForChoice(
                    $PromptForChoiceTitle, 
                    $Title, 
                    $Choices, 
                    0
                )

                $Output = $AllInputObjects | select -Skip $Result -First 1

            }
        }

        if ($Output -eq $null) {
            Write-Error "Selection cancelled"
        }
        else {
            $Output
        }
    }
}

if ($PSVersionTable.PSVersion -ge "3.0") {
# Long path names only supported on PS version 3.0 or greater
# Used for long filename support:
Add-Type -Path "$PSScriptRoot\bin\Microsoft.Experimental.IO.dll"

    function Resolve-Path {
    <#
    Proxy function used for very basic long path support. If resolve-path cmdlet encounters and error, this
    function will catch it, and attempt to use the experimental io library to resolve the path as a long
    directory name or long file name.

    #>

        [CmdletBinding(DefaultParameterSetName='Path', SupportsTransactions=$true)] #, HelpUri='http://go.microsoft.com/fwlink/?LinkID=113384')]
        param(
            [Parameter(ParameterSetName='Path', Mandatory=$true, Position=0, ValueFromPipeline=$true, ValueFromPipelineByPropertyName=$true)]
            [string[]]
            ${Path},

            [Parameter(ParameterSetName='LiteralPath', Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
            [Alias('PSPath')]
            [string[]]
            ${LiteralPath},

            [switch]
            ${Relative},

            [Parameter(ValueFromPipelineByPropertyName=$true)]
            [pscredential]
            ${Credential})

        begin
        {

            try {
                $outBuffer = $null
                if ($PSBoundParameters.TryGetValue('OutBuffer', [ref]$outBuffer))
                {
                    $PSBoundParameters['OutBuffer'] = 1
                }
                $wrappedCmd = $ExecutionContext.InvokeCommand.GetCommand('Resolve-Path', [System.Management.Automation.CommandTypes]::Cmdlet)

                #region PAC module addition
                $PSBoundParameters.ErrorVariable = "__ResolvePathErrors"
                $PSBoundParameters.ErrorAction = "SilentlyContinue"
                #endregion

                $scriptCmd = { & $wrappedCmd @PSBoundParameters }
                $steppablePipeline = $scriptCmd.GetSteppablePipeline($myInvocation.CommandOrigin)
                $steppablePipeline.Begin($PSCmdlet)
            } catch {
                throw
            }
        }

        process
        {
            try {
                $steppablePipeline.Process($_)
            } 
            catch {
                throw
            }

            #region PAC module addition
            if ($__ResolvePathErrors) {
    
                $ErrorsToWrite = @()
                foreach ($CurrentError in ($__ResolvePathErrors | select -Unique)) {  # For some reason, Resolve-Path sometimes outputs duplicate errors

                    $ResolvedLongPaths = if ($_) {
                        ResolveLongPath $_
                    }
                    else {
                        foreach ($CurrentPath in $Path) {
                            ResolveLongPath $CurrentPath
                        }
                    }

                    if ($ResolvedLongPaths) {
                        $ResolvedLongPaths
                    }
                    else {
                        $ErrorsToWrite += $CurrentError
                    }
                }

                # All errors have either been dealt with or written back out. Clear them:
                foreach ($CurrentError in $ErrorsToWrite) {
                    Write-Error $CurrentError
                }
                $__ResolvePathErrors.Clear()
            }
            #endregion
        }

        end
        {
            try {
                $steppablePipeline.End()
            } catch {
                throw
            }
        }
        <#

        .ForwardHelpTargetName Resolve-Path
        .ForwardHelpCategory Cmdlet

        #>
    }

    function ResolveLongPath {
    <#
    When Resolve-Path encounters an error, this function is used to check to see if the path was a 
    long path:
    #>
        [CmdletBinding()]
        param(
            [Parameter(Mandatory=$true)]
            [string] $Path,
            [string] $SearchPattern
        )

        $ProviderPrefix = "PowerShellAccessControl"

        if (-not $Path) { return }

        try {
            if (-not $SearchPattern) {
                if ([Microsoft.Experimental.IO.LongPathDirectory]::Exists($Path)) {
                    $Type = "directory"
                }
                elseif ([Microsoft.Experimental.IO.LongPathFile]::Exists($Path)) {
                    $Type = "file"
                }
                else {
                    throw "syntax is incorrect"
                }

                New-Object PSObject -Property @{
                    Path = $Path
                    Provider = "$ProviderPrefix$Type"
                }
            }
            else {
                [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateDirectories($Path, $SearchPattern) | ForEach-Object {
                    New-Object PSObject -Property @{
                        Path = $_
                        Provider = "${ProviderPrefix}Directory"
                    }
                }
                [Microsoft.Experimental.IO.LongPathDirectory]::EnumerateFiles($Path, $SearchPattern) | ForEach-Object {
                    New-Object PSObject -Property @{
                        Path = $_
                        Provider = "${ProviderPrefix}File"
                    }
                }
            }
        }
        catch {
            if ($_.Exception.Message -match "syntax is incorrect") {
                $Params = @{
                    Path = Split-Path $Path -Parent
                    SearchPattern = Split-Path $Path -Leaf
                }

                ResolveLongPath @Params -ErrorAction SilentlyContinue | ForEach-Object {
                    if ($SearchPattern) {
                        ResolveLongPath -Path $_.Path -SearchPattern $SearchPattern
                    }
                    else {
                        $_
                    }
                }
            }
            else {
                # Write the error as is
                Write-Error $_
            }
        }
    }
}

function GetDefaultAppliesTo {
<#
Different types of objects have ACEs that have a different "AppliesTo" value. For example, folders default to
"Object, ChildContains, ChildObjects", files to just "Object", registry keys to "Object, ChildContainers", etc.

This function takes the access mask enumeration and a boolean value telling whether or not the ACE belongs to
a container object (like a folder or registry entry), and outputs the default "AppliesTo" enumeration value.
#>

    [CmdletBinding()]
    param(
        $AccessMaskEnumeration,
        [switch] $IsContainer = $false
    )

    # SDs have ACEs that apply to their object by default:
    $AppliesTo = [PowerShellAccessControl.AppliesTo]::Object

    if ($IsContainer) {
        # If the SD belongs to container, ACEs also apply to child containers by default:
        $AppliesTo = $AppliesTo -bor [PowerShellAccessControl.AppliesTo]::ChildContainers

        # ACEs apply to child objects if they are folders. Switch statement used in case there
        # are future types that need a special handling
        switch ($AccessMaskEnumeration.FullName) {

            System.Security.AccessControl.FileSystemRights {
                $AppliesTo = $AppliesTo -bor [PowerShellAccessControl.AppliesTo]::ChildObjects
            }
        }
    }

    [PowerShellAccessControl.AppliesTo] $AppliesTo
}

function GetCentralAccessPolicy {
<#
Currently just messing around with retrieving CAPs. This relies on the ActiveDirectory module,
and since the function doesn't need that, this will fail miserably on a system that doesn't
have it. Once CAPs are officially supported, ActiveDirectory module dependence will be removed.

#>
param(
    $SDObject
)
    if ($__OsVersion -lt "6.2") {
        return
    }

    $BinaryScopeInfo = GetSecurityInfo -Path $SDObject.Path -ObjectType $SDObject.ObjectType -SecurityInformation Scope

    $SD = New-Object System.Security.AccessControl.RawSecurityDescriptor (([byte[]] $BinaryScopeInfo), 0)

    # AceType of 19 is what holds the info we want:
    $SD.SystemAcl | 
        where { [int] $_.AceType -eq 19 } |
        ForEach-Object {

            $Data = $_.GetOpaque()
            $NewAceParams = @{
                Principal = New-Object System.Security.Principal.SecurityIdentifier ($Data, 4)
                AccessMask = [System.BitConverter]::ToInt32($Data, 0)
                AppliesTo = $_ | GetAppliesToMapping
                OnlyApplyToThisContainer = $_ | GetAppliesToMapping -CheckForNoPropagateInherit
            }
            $Ace = New-AccessControlEntry @NewAceParams

            $Policy = Get-ADCentralAccessPolicy -Filter { policyID -eq $Ace.SecurityIdentifier } -ErrorAction SilentlyContinue
            if ($Policy) {
                $Rules = $Policy.Members | Get-ADCentralAccessRule

                # PSCustomObject is OK since CAP will only apply on systems that have PS > 2
                $Policy = [PSCustomObject] @{
                    Policy = $Policy
                    Rules = $Rules
                }
            }

                    
            # There are a few things that still need fixing
            $Ace | Add-Member -NotePropertyMembers @{
                AceType = "CentralAccessPolicy"
                IsInherited = $_.IsInherited
                Policy = $Policy
            } -Force

            $Ace
        }
}

filter ModifySearchRegex {
<#
There are a few places where a regex is used, but I wanted a *
to be replaced with a .*

I also wanted a way for the user to still escape the * so that
they could use one in a proper regex. Just in case the steps
I came up with were wrong, I wanted to have the replacement
handled somewhere else so I would just have to make changes in
one place in the future.

This replaces a single asterisk with a .*
If it encounteres a double asterisk, **, it will not do the .*
replacement, but it will replace it with a single asterisk.
#>
    $Temp = $_ -replace "(?<!\*)\*(?!\*)", ".*"
    $Temp -replace "\*\*", "*"

}
