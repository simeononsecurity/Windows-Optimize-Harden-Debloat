# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\AuditPolicyRule.psm1
using namespace System.Text
# Header

<#
    .SYNOPSIS
        Converts the xccdf check-content element into an audit policy object.
#>
class AuditPolicyRuleConvert : AuditPolicyRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    AuditPolicyRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Audit Policy Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    AuditPolicyRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $tokens = $this.ExtractProperties()
        $this.SetSubcategory($tokens)
        $this.SetAuditFlag($tokens)
        $this.Ensure = [Ensure]::Present
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    <#
        .SYNOPSIS
            Extracts and returns the audit policy settings from the check-content.
        .DESCRIPTION
            This match looks for the following patterns
            1. Category >> Subcategory - AuditFlag
            2. Category -> Subcategory - AuditFlag
        .NOTES
            If any rule does not match this pattern, please update the xccdf
            change log file to align to one of these options.
    #>
    [RegularExpressions.MatchCollection] ExtractProperties ()
    {
        return [regex]::Matches(
            $this.RawString,
            '(?:(?:\w+(?:\s|\/))+(?:(?: >|>|-)>(?:\s+)?))(?<subcategory>(?:.+?(?=\s-\s)))\s-\s(?<auditflag>(?:\w+)+)'
        )
    }

    <#
        .SYNOPSIS
            Set the subcategory name
        .DESCRIPTION
            Set the subcategory value. If the returned audit policy subcategory
            is not valid, the parser status is set to fail.
    #>
    [void] SetSubcategory ([RegularExpressions.MatchCollection] $Regex)
    {
        $thisSubcategory = $regex.Groups.Where(
            {$_.Name -eq 'subcategory'}
        ).Value

        if (-not $this.SetStatus($thisSubcategory))
        {
            $this.set_Subcategory($thisSubcategory.trim())
        }
    }

    <#
        .SYNOPSIS
            Set the subcategory flag
        .DESCRIPTION
            Set the subcategory flag. If the returned audit policy subcategory
            is not valid, the parser status is set to fail.
    #>
    [void] SetAuditFlag ([RegularExpressions.MatchCollection] $Regex)
    {
        $thisAuditFlag = $Regex.Groups.Where(
            {$_.Name -eq 'auditflag'}
        ).Value

        if (-not $this.SetStatus($thisAuditFlag))
        {
            $this.set_AuditFlag($thisAuditFlag)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'AuditPolicySubcategory'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    <#
        .SYNOPSIS
            Checks if a rule matches an audit policy setting.
    #>
    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match "\bAuditpol\b" -and
            $CheckContent -NotMatch "resourceSACL"
        )
        {
            return $true
        }
        return $false
    }
}
