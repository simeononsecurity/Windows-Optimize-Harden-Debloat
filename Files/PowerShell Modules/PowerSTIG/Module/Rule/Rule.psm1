# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt', '*.md', '*.psm1', 'data.*.ps1')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Recurse -File -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
#header

<#
    .SYNOPSIS
        The base class for all STIG rule types
    .DESCRIPTION
        The base class for all STIG rule types to support a common initializer and
        set of methods that apply to all rule types. PowerShell does not support
        abstract classes, but this class is not intended to be used directly.
    .PARAMETER Id
        The STIG ID
    .PARAMETER Title
        Title string from STIG
    .PARAMETER Severity
        Severity data from STIG
    .PARAMETER ConversionStatus
        Module processing status of the raw string
    .PARAMETER RawString
        The raw string from the check-content element of the STIG item
    .PARAMETER SplitCheckContent
        The raw check string split into multiple lines for pattern matching
    .PARAMETER IsNullOrEmpty
        A flag to determine if a value is supposed to be empty or not.
        Some items should be empty, but there needs to be a way to validate that empty is on purpose.
    .PARAMETER OrganizationValueRequired
        A flag to determine if a local organizational setting is required.
    .PARAMETER OrganizationValueTestString
        A string that can be invoked to test the chosen organizational value.
    .PARAMETER DscResource
        Defines the DSC resource used to configure the rule
#>
class Rule : ICloneable
{
    [string] $Id
    [string] $Title
    [severity] $Severity
    [status] $ConversionStatus
    [string] $DscResource
    [string] $DuplicateOf
    [string] $Description
    [Boolean] $IsNullOrEmpty
    [Boolean] $OrganizationValueRequired
    [string] $OrganizationValueTestString
    [string] $RawString
    hidden [string[]] $SplitCheckContent

    <#
        .SYNOPSIS
            Default constructor
        .DESCRIPTION
            This is the base class constructor
    #>
    Rule ()
    {
    }

    <#
        .SYNOPSIS
            PowerSTIG XML deserialze constructor
        .DESCRIPTION
            This constructor laods all properties from from the calling child
            class the PowerSTIG XML
        .PARAMETER Rule
            The STIG rule to load from PowerSTIG processed data
    #>
    Rule ([xml.xmlelement] $Rule)
    {
        $propertyList = ($this | Get-Member -MemberType Properties).Name

        foreach ($property in $propertyList)
        {
            if ( -not [string]::IsNullOrEmpty($Rule.($property)) )
            {
                $this.($property) = $Rule.($property)
            }
            if ($property -eq 'OrganizationValueRequired')
            {
                # When a bool is evaluated if anything exists it is true, so we need provide a bool
                $this.OrganizationValueRequired = ($Rule.OrganizationValueRequired -eq 'true')
            }
        }
    }

    <#
        .SYNOPSIS
            XCCDF XML constructor
        .DESCRIPTION
            This is the base class constructor
    #>
    Rule ([xml.xmlelement] $Rule, [switch] $Convert)
    {
        # This relaces the current Invokeclass method
        $this.Id = $Rule.Id
        $this.Title = $Rule.Title
        $this.Severity = $Rule.rule.severity
        $this.Description = $Rule.rule.description
        if ( Test-HtmlEncoding -CheckString  $Rule.rule.Check.('check-content') )
        {
            $this.RawString = ( ConvertFrom-HtmlEncoding -CheckString $Rule.rule.Check.('check-content') )
        }
        else
        {
            $this.RawString = $Rule.rule.Check.('check-content')
        }

        $this.SplitCheckContent = [Rule]::SplitCheckContent( $this.rawString )

        $this.IsNullOrEmpty = $false
        $this.OrganizationValueRequired = $false
    }

    #region Methods

    <#
        This method is needed in each convert class for a couple of reasons.
        1. PSTypeConverter has to be implemented at a .NET type, which might cause issues with customers that use constrained language mode.
        2. The parent class modules cannot load the child class modules (load loop)
    #>
    hidden [psobject] AsRule()
    {
        # Create an instance of the convert rule parent class
        $parentRule = $this.GetType().BaseType::new()
        # Get the property list from the convert rule
        $propertyList = $this | Get-Member -MemberType Properties
        # Copy the convert properties to the parent properties
        foreach ($property in $propertyList)
        {
            if ( $null -ne $this.($property.Name) )
            {
                $parentRule.($property.Name) = $this.($property.Name)
            }
        }
        return $parentRule
    }

    <#
        .SYNOPSIS
            Returns the rule property to override based on the override tag
    #>
    hidden [string] GetOverrideValue()
    {
        # The path that is returned from GetType contains wierd backslashes that I can't figure out how to use.
        $moduleName = $this.GetType().Name -replace 'Rule', ''
        $baseclassPath = Resolve-Path -Path "$PSScriptRoot\..\Rule.$moduleName\$($this.GetType().Name).psm1"
        # Exception property tag is used in the base class to identify the property that is to be overridden
        # the patteren is as follows
        # [type] $Name <#(ExceptionValue)#>
        $exceptionPropertyTag = '\s+(?:\[\w+(?:\[\s*\])?\])\s\$(?<ExceptionValue>\w+)\s+<#\(ExceptionValue\)#>'
        $exceptionProperty = [regex]::Matches(
            (Get-Content -path $baseclassPath -raw), $exceptionPropertyTag
        ).Groups.Where( {$_.Name -eq 'ExceptionValue'}).Value

        return $exceptionProperty
    }

    <#
        .SYNOPSIS
            Applies an org setting to a rule
    #>
    [void] AddOrgSetting ([hashtable] $OrgSettingParamValue)
    {
        foreach ($key in $OrgSettingParamValue.Keys)
        {
            $this.$key = $OrgSettingParamValue[$key]
        }
    }

    <#
        .SYNOPSIS
            Applies an exception to a rule
    #>
    [void] AddExceptionToPolicy ([object] $ExceptionParamValue)
    {
        $this.UpdateRuleTitle('Exception')
        if ($ExceptionParamValue -is [hashtable])
        {
            foreach ($key in $ExceptionParamValue.Keys)
            {
                $this.$key = $ExceptionParamValue[$key]
            }
        }
        else
        {
            $this.($this.GetOverrideValue()) = $ExceptionParamValue
        }
    }

    <#
    .SYNOPSIS
        Applies a uniform title update format
    #>
    [void] UpdateRuleTitle ([string] $Value)
    {
        $this.Title = "[$Value] " + $this.Title
    }

    <#
        .SYNOPSIS
            Creates a shallow copy of the current object
    #>
    hidden [Object] Clone ()
    {
        return $this.MemberwiseClone()
    }

    <#
        .SYNOPSIS
            Tests if the rule already exists
        .DESCRIPTION
            Compares the rule with existing converted rules
        .PARAMETER ReferenceObject
            The existing converted rules
    #>
    hidden [void] SetDuplicateRule ()
    {
        $val = Test-DuplicateRule -ReferenceObject $global:stigSettings -DifferenceObject $this
        if ($val)
        {
           $this.DuplicateOf = $val
        }
    }

    <#
        .SYNOPSIS
            Sets the conversion status
        .DESCRIPTION
            Sets the conversion status
        .PARAMETER Value
            The value to be tested
    #>
    hidden [Boolean] SetStatus ( [String] $Value )
    {
        if ( [String]::IsNullOrEmpty( $Value ) )
        {
            $this.conversionstatus = [status]::fail
            return $true
        }
        else
        {
            return $false
        }
    }

    <#
        .SYNOPSIS
            Sets the conversion status with an allowed blank value
        .DESCRIPTION
            Sets the conversion status with an allowed blank value
        .PARAMETER Value
            The value to be tested
        .PARAMETER AllowNullOrEmpty
            A flag to allow blank values
    #>
    hidden [Boolean] SetStatus ( [String] $Value, [Boolean] $AllowNullOrEmpty )
    {
        if ( [String]::IsNullOrEmpty( $Value ) -and -not $AllowNullOrEmpty )
        {
            $this.conversionstatus = [status]::fail
            return $true
        }
        else
        {
            return $false
        }
    }

    <#
        .SYNOPSIS
            Sets the IsNullOrEmpty value to true
        .DESCRIPTION
            Sets the IsNullOrEmpty value to true
    #>
    hidden [void] SetIsNullOrEmpty ()
    {
        $this.IsNullOrEmpty = $true
    }

    <#
        .SYNOPSIS
            Sets the OrganizationValueRequired value to true
        .DESCRIPTION
            Sets the OrganizationValueRequired value to true
    #>
    hidden [void] SetOrganizationValueRequired ()
    {
        $this.OrganizationValueRequired = $true
    }

    <#
        .SYNOPSIS
            Gets the organization value test string
        .DESCRIPTION
            Gets the organization value test string
        .PARAMETER TestString
            The string to extract the
    #>
    hidden [string] GetOrganizationValueTestString ( [String] $TestString )
    {
        return Get-OrganizationValueTestString -String $TestString
    }

    <#
        .SYNOPSIS
            Converts the object into a hashtable
        .DESCRIPTION
            Converts the object into a hashtable
    #>
    <#{TODO}#> # remove and cleanup testhelper.psm1
    hidden [hashtable] ConvertToHashTable ()
    {
        return ConvertTo-HashTable -InputObject $this
    }

    <#
        .SYNOPSIS
            Splits the check-content element in the xccdf into an array
        .DESCRIPTION
            Splits the check-content element in the xccdf into an array
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    hidden static [string[]] SplitCheckContent ( [String] $CheckContent )
    {
        return (
            $CheckContent -split '\n' |
                Select-String -Pattern "\w" |
                ForEach-Object { $PSitem.ToString().Trim() }
        )
    }

    <#
        .SYNOPSIS
            Get the fixtext from the xccdf
        .DESCRIPTION
            Get the fixtext from the xccdf
        .PARAMETER StigRule
            The StigRule to extract the fix text from
    #>
    hidden static [string[]] GetFixText ( [xml.xmlelement] $StigRule )
    {
        $fullFix = $StigRule.Rule.fixtext.'#text'

        $return = $fullFix -split '\n' |
            Select-String -Pattern "\w" |
            ForEach-Object { $PSitem.ToString().Trim() }

        return $return
    }

    <#
        .SYNOPSIS
            Looks for the rule to see if it already exists
        .DESCRIPTION
            Looks for the rule to see if it already exists
        .PARAMETER RuleCollection
            The global rule collection
    #>
    hidden [bool] IsExistingRule ( [object] $RuleCollection )
    {
        return Test-ExistingRule -RuleCollection $RuleCollection $this
    }

    #endregion
    #region Hard coded Methods

    <#
        .SYNOPSIS
            Checks to see if the STIG is a hard coded return value
        .DESCRIPTION
            Accepts defeat in that the STIG string data for a select few checks
            are too unwieldy to parse properly. The OVAL data does not provide
            much more help in a few of the cases, so the STIG Id's for these
            checks are hardcoded here to force a fixed value to be returned.
    #>
    hidden [bool] IsHardCoded ()
    {
        return Test-ValueDataIsHardCoded -StigId $this.id
    }

    <#
        .SYNOPSIS
            Returns a hard coded conversion value
        .DESCRIPTION
            Returns a hard coded conversion value
    #>
    hidden [string] GetHardCodedString ()
    {
        return Get-HardCodedString -StigId $this.id
    }

    <#
        .SYNOPSIS
            Checks to see if the STIG org value is a hard coded return value
        .DESCRIPTION
            Accepts defeat in that the STIG string data for a select few checks
            are too unwieldy to parse properly. The OVAL data does not provide
            much more help in a few of the cases, so the STIG Id's for these
            checks are hardcoded here to force a fixed value to be returned.
    #>
    hidden [bool] IsHardCodedOrganizationValueTestString ()
    {
        return Test-IsHardCodedOrganizationValueTestString -StigId $this.id
    }

    <#
        .SYNOPSIS
            Returns a hard coded org value
        .DESCRIPTION
            Returns a hard coded org value
    #>
    hidden [string] GetHardCodedOrganizationValueTestString ()
    {
        return Get-HardCodedOrganizationValueTestString -StigId $this.id
    }

    <#{TODO}#> <#Remove

    hidden [void] SetDscResource ()
    {
        throw 'SetDscResource must be implemented in the child class'
    }
    #>
    #endregion
}
