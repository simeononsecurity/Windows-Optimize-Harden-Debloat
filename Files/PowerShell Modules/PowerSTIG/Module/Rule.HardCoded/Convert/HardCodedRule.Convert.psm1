# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\..\Rule.AccountPolicy\AccountPolicyRule.psm1
using module .\..\..\Rule.AuditPolicy\AuditPolicyRule.psm1
using module .\..\..\Rule.DnsServerRootHint\DnsServerRootHintRule.psm1
using module .\..\..\Rule.DnsServerSetting\DnsServerSettingRule.psm1
using module .\..\..\Rule.Document\DocumentRule.psm1
using module .\..\..\Rule.FileContent\FileContentRule.psm1
using module .\..\..\Rule.Group\GroupRule.psm1
using module .\..\..\Rule.IISLogging\IISLoggingRule.psm1
using module .\..\..\Rule.Manual\ManualRule.psm1
using module .\..\..\Rule.MimeType\MimeTypeRule.psm1
using module .\..\..\Rule.Permission\PermissionRule.psm1
using module .\..\..\Rule.ProcessMitigation\ProcessMitigationRule.psm1
using module .\..\..\Rule.Registry\RegistryRule.psm1
using module .\..\..\Rule.SecurityOption\SecurityOptionRule.psm1
using module .\..\..\Rule.Service\ServiceRule.psm1
using module .\..\..\Rule.SqlScriptQuery\SqlScriptQueryRule.psm1
using module .\..\..\Rule.UserRight\UserRightRule.psm1
using module .\..\..\Rule.WebAppPool\WebAppPoolRule.psm1
using module .\..\..\Rule.WebConfigurationProperty\WebConfigurationPropertyRule.psm1
using module .\..\..\Rule.WindowsFeature\WindowsFeatureRule.psm1
using module .\..\..\Rule.WinEventLog\WinEventLogRule.psm1
using module .\..\..\Rule.AuditSetting\AuditSettingRule.psm1
using module .\..\..\Rule.SslSettings\SslSettingsRule.psm1
using module .\..\..\Rule.WindowsFeature\Convert\WindowsFeatureRule.Convert.psm1

<#
    .SYNOPSIS
        Identifies and extracts the Hard Coded details from an xccdf rule, that
        has specific replace text defined in the xml log file.
    .DESCRIPTION
        The class is used to convert the rule check-content element into a
        given rule type object. The rule check content is parsed to identify
        a predefined rule type. The configuration details are then extracted
        and validated before returning the object.
#>
class HardCodedRuleConvert
{
    [System.Object] $Rule
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    HardCodedRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Constructor that accepts a XccdfRule [xml.xmlement] which
            converts to the correct rule type based on the modified check
            content.
        .PARAMETER XccdfRule
            XML representation of the unprocessed STIG Rule.
    #>
    HardCodedRuleConvert ([xml.xmlelement] $XccdfRule)
    {
        $ruleType = Get-HardCodedRuleType -CheckContent $XccdfRule.Rule.Check.'check-content'
        $this.Rule = $this.SetRule($XccdfRule, $ruleType)
    }

    #region Methods

    <#
        .SYNOPSIS
            SetRule method creates a new instance of the specified Rule Type
            and sets the correct properties based on the modified check
            content.
        .PARAMETER XccdfRule
            XML representation of the unprocessed STIG Rule.
        .PARAMETER TypeName
            The TypeName for the Rule to be converted
    #>
    [object] SetRule ([xml.xmlelement] $XccdfRule, [string] $TypeName)
    {
        $newRule = New-Object -TypeName $TypeName -ArgumentList $XccdfRule
        $propertyHashtable = Get-HardCodedRuleProperty -CheckContent $XccdfRule.Rule.Check.'check-content'
        foreach ($property in $propertyHashtable.Keys)
        {
            $newRule.$property = $propertyHashtable[$property]
        }
        if ($propertyHashtable.ContainsValue($null) -or $propertyHashtable.Keys.Count -le 1)
        {
            $newRule.set_OrganizationValueRequired($true)
        }
        $newRule.set_Severity($XccdfRule.rule.severity)
        $newRule.set_Description($XccdfRule.rule.description)
        $newRule.set_RawString($XccdfRule.Rule.check.'check-content')
        return $newRule
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -Match 'HardCodedRule')
        {
            return $true
        }
        return $false
    }

    static [bool] HasMultipleRules ([string] $CheckContent)
    {
        $ruleTypeMatch = Split-HardCodedRule -CheckContent $CheckContent
        if ($ruleTypeMatch.Count -gt 1)
        {
            return $true
        }
        return $false
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. Each split rule id is appended with a dot and letter
            to keep reporting per the ID consistent, i.e. V-1000.a or V-1000.b.
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [string[]] SplitMultipleRules ([string] $CheckContent)
    {
        $ruleResourceInformation = Split-HardCodedRule -CheckContent $CheckContent
        return $ruleResourceInformation
    }

    hidden [psobject] AsRule ()
    {
        $parentRule = $this.Rule
        return $parentRule
    }
#endregion
}
