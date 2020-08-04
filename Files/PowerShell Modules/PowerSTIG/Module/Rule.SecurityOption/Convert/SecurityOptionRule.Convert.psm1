# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\SecurityOptionRule.psm1
using namespace System.Text
# Header

<#
    .SYNOPSIS
        Identifies and extracts the Security Option details from an xccdf rule.
    .DESCRIPTION
        The class is used to convert the rule check-content element into an
        Security Option object. The rule content is parsed to identify it as a
        Security Option rule. The configuration details are then extracted and
        validated before returning the object.
#>
class SecurityOptionRuleConvert : SecurityOptionRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    SecurityOptionRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Security Option Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    SecurityOptionRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        [System.Text.RegularExpressions.Match] $tokens = $this.ExtractProperties()
        $this.SetOptionName($tokens)
        $this.SetOptionValue($tokens)
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts and returns the Security Option settings from the check-content.
        .DESCRIPTION
            This match looks for the following patterns
            1. If "OptionName" * "Value"
            2. If the value for "OptionName" * "Value"
                This has only been found in the SQL instance STIG
        .NOTES
            If any rule does not match this pattern, please update the xccdf
            change log file to align to one of these options.
    #>
    [System.Text.RegularExpressions.Match] ExtractProperties ()
    {
        return [regex]::Match(
            $this.RawString,
            '(?:If\s(?:the\svalue\sfor\s)?")(?<optionName>[^"]+)(?:")[^"]+(?:")(?<optionValue>[^"]+)(?:")'
        )
    }

    <#
        .SYNOPSIS
            Sets the Security Option name that was extracted from the xccdf.
        .DESCRIPTION
            Gets the Security Option name token from the regular expression match
            group and sets the policy Name. If the named group is null, the
            convert status is set to fail.
    #>
    [void] SetOptionName ([System.Text.RegularExpressions.Match] $Regex)
    {
        $thisOptionName = $Regex.Groups.Where( {$_.Name -eq 'OptionName'}).Value

        if (-not $this.SetStatus($thisOptionName))
        {
            $this.set_OptionName($thisOptionName)
        }
    }

    <#
        .SYNOPSIS
            Sets the Security Option value that was extracted from the xccdf.
        .DESCRIPTION
            Gets the Security Option value token from the regular expression match
            group and sets the policy value. If the named group is null, the
            convert status is set to fail.
    #>
    [void] SetOptionValue ([System.Text.RegularExpressions.Match] $Regex)
    {
        if ($this.OptionValueContainsRange())
        {
            $this.SetOptionOrganizationValue()
        }
        else
        {
            $thisOptionValue = $Regex.Groups.Where( {$_.Name -eq 'OptionValue'}).Value
            if (-not $this.SetStatus($thisOptionValue))
            {
                $this.set_OptionValue($thisOptionValue)
            }
        }
    }

    <#
        .SYNOPSIS
            Looks for a range of values defined in the rule.
        .DESCRIPTION
            A regular expression is applied to the rule to look for key words
            and sentence structures that define a list of valid values. If a
            range is detected the test returns true and false if not.
    #>
    [bool] OptionValueContainsRange ()
    {
        if (Test-SecurityPolicyContainsRange -CheckContent $this.SplitCheckContent)
        {
            return $true
        }
        return $false
    }
    <#
        .SYNOPSIS
            Sets the organizational value with the correct range.
        .DESCRIPTION
            The range of valid values is enforced in the organizational settings
            with a PowerShell expression. The range of values are extracted and
            converted into a PS expression that is evaluated when the rule is
            loaded. For example, if a value is allowed to be between 1 and 3,
            the user provided org setting will be evaluated to ensure that they
            are within policy guide lines and throw an error if not.
    #>
    [void] SetOptionOrganizationValue ()
    {
        $this.set_OrganizationValueRequired($true)

        $thisPolicyValueTestString = Get-SecurityPolicyOrganizationValueTestString -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisPolicyValueTestString))
        {
            $this.set_OrganizationValueTestString($thisPolicyValueTestString)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'SecurityOption'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    <#
        .SYNOPSIS
            looks for the Security Option path to determine if the rule
            is configuring an Security Option.
    #>
    static [bool] Match ([string] $CheckContent)
    {
        <#
            .Net does not appear to support regex subroutines, so we add and
            expand a variable before the match is evaluated.
        #>
        $delimiter = '(?:(?:-|>)>)'
        return ($CheckContent -Match
            "(?:Local Security Policy|Security Settings) $delimiter Local Policies $delimiter Security Options" )
    }
    #endregion
}
