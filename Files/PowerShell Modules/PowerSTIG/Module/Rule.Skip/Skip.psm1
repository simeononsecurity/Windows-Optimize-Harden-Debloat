# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Rule\Rule.psm1

<#
    .SYNOPSIS
        This class describes a SkippedRule
    .DESCRIPTION
        The SkippedRule class describes a SkippedRule, the rule id of a specific Stig rule that should be excluded from the Stigs that need to be
        processed. The SkippedRule class instance will move the specific Stig rule into a SkippedRule section of the StigData output Xml so that
        it is documented as having been skipped.
    .PARAMETER StigRuleId
        The Id of an individual Stig Rule
    .EXAMPLE
        $skippedRule = [SkippedRule]::new('V-1090')
    .NOTES
        This class requires PowerShell v5 or above.
#>
class SkippedRule : Rule
{
    <#
        .SYNOPSIS
            DO NOT USE - For testing only
        .DESCRIPTION
            A parameterless constructor for SkippedRule. To be used only for
            build/unit testing purposes as Pester currently requires it in order to test
            static methods on powershell classes
    #>
    SkippedRule ()
    {
        Write-Warning "This constructor is for build testing only."
    }

    <#
        .SYNOPSIS
            A constructor for SkippedRule. Returns a ready to use instance of SkippedRule.
        .DESCRIPTION
            A constructor for SkippedRule. Returns a ready to use instance
            of SkippedRule.
        .PARAMETER Rule
            The Stig Rule
    #>
    SkippedRule ([xml.xmlelement] $Rule) : base ($Rule)
    {
        $this.UpdateRuleTitle('Skip')
    }
}
