# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\AccountPolicyRule.psm1
using namespace System.Text
# Header

<#
    .SYNOPSIS
        Identifies and extracts the Account Policy details from an xccdf rule.
    .DESCRIPTION
        The class is used to convert the rule check-content element into an
        Account Policy object. The rule content is parsed to identify it as an
        Account Policy rule. The configuration details are then extracted and
        validated before returning the object.
#>
class AccountPolicyRuleConvert : AccountPolicyRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    AccountPolicyRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Account Policy Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    AccountPolicyRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        [RegularExpressions.MatchCollection] $tokens = $this.ExtractProperties()
        $this.SetPolicyName($tokens)
        $this.SetPolicyValue($tokens)
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts and returns the account policy settings from the check-content.
        .DESCRIPTION
            This match looks for the following patterns
            1. If the "PolicyName" * "Value"
            2. If the value for "PolicyName" * "Value"
            3. If the value for the "PolicyName" * "Value"
        .NOTES
            If any rule does not match this pattern, please update the xccdf
            change log file to align to one of these options.
    #>
    [RegularExpressions.MatchCollection] ExtractProperties ()
    {
        return [regex]::Matches(
            $this.RawString,
            '(?:If the (?:value for (?:the )?)?")(?<policyName>[^"]+)(?:")[^"]+(?:")(?<policyValue>[^"]+)(?:")'
        )
    }

    <#
        .SYNOPSIS
            Sets the account policy name that was extracted from the xccdf.
        .DESCRIPTION
            Gets the account policy name token from the regular expression match
            group and sets the policy Name. If the named group is null, the
            convert status is set to fail.
    #>
    [void] SetPolicyName ([RegularExpressions.MatchCollection] $Regex)
    {
        $thisPolicyName = $Regex.Groups.Where({$_.Name -eq 'policyName'}).Value

        if (-not $this.SetStatus($thisPolicyName))
        {
            $this.set_PolicyName($thisPolicyName)
        }
    }

    <#
        .SYNOPSIS
           Sets the account policy value that was extracted from the xccdf.
        .DESCRIPTION
            Gets the account policy value token from the regular expression match
            group and sets the policy value. If the named group is null, the
            convert status is set to fail.
    #>
    [void] SetPolicyValue ([RegularExpressions.MatchCollection] $Regex)
    {
        if ($this.PolicyValueContainsRange())
        {
            $this.SetPolicyOrganizationValue()
        }
        else
        {
            $thisPolicyValue = $Regex.Groups.Where({$_.Name -eq 'policyValue'}).Value

            if (-not $this.SetStatus($thisPolicyValue))
            {
                $this.set_PolicyValue($thisPolicyValue)
            }
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'AccountPolicy'
        }
        else
        {
            $this.DscResource = 'None'
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
    [bool] PolicyValueContainsRange ()
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
    [void] SetPolicyOrganizationValue ()
    {
        $this.set_OrganizationValueRequired($true)

        $thisPolicyValueTestString = Get-SecurityPolicyOrganizationValueTestString -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisPolicyValueTestString))
        {
            $this.set_OrganizationValueTestString($thisPolicyValueTestString)
        }
    }

    <#
        .SYNOPSIS
            looks for the Account Policy settings path to determine if the rule
            is configuring an Account Policy Setting.
    #>
    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -Match 'Navigate to.+Windows Settings\s*(-|>)?>\s*Security Settings\s*(-|>)?>\s*Account Policies')
        {
            return $true
        }
        return $false
    }
    #endregion
}
