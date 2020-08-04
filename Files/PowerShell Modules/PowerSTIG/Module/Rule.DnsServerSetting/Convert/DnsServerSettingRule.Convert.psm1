# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\DnsServerSettingRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into an Dns Server
        Setting object
    .DESCRIPTION
        The DnsServerSettingRuleConvert class is used to extract the Dns Server settings
        from the check-content of the xccdf. Once a STIG rule is identified as a
        DNS server setting, it is passed to the DnsServerSettingRuleConvert class for
        parsing and validation.

#>
class DnsServerSettingRuleConvert : DnsServerSettingRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    DnsServerSettingRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Dns Server Setting Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    DnsServerSettingRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetDnsServerPropertyName()
        $this.SetDnsServerPropertyValue()
        $this.SetDuplicateRule()
        if ($this.IsExistingRule($global:stigSettings))
        {
            $newId = Get-AvailableId -Id $this.Id
            $this.set_id($newId)
        }

        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the DNS server setting name from the check-content and sets
            the value
        .DESCRIPTION
            Gets the DNS server setting name from the xccdf content and sets the
            value. If the DNS server setting that is returned is not a valid name,
            the parser status is set to fail.
    #>
    [void] SetDnsServerPropertyName ()
    {
        $thisDnsServerSettingPropertyName = Get-DnsServerSettingProperty -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisDnsServerSettingPropertyName))
        {
            $this.set_PropertyName($thisDnsServerSettingPropertyName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the DNS server setting value from the check-content and
            sets the value
        .DESCRIPTION
            Gets the DNS server setting value from the xccdf content and sets
            the value. If the DNS server setting that is returned is not a valid
            property, the parser status is set to fail.
    #>
    [void] SetDnsServerPropertyValue ()
    {
        $thisDnsServerSettingPropertyValue = Get-DnsServerSettingPropertyValue -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisDnsServerSettingPropertyValue))
        {
            $this.set_PropertyValue($thisDnsServerSettingPropertyValue)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'xDnsServerSetting'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match 'dnsmgmt\.msc' -and
            $CheckContent -NotMatch 'Forward Lookup Zones' -and
            $CheckContent -Notmatch 'Logs\\Microsoft' -and
            $CheckContent -NotMatch 'Verify the \"root hints\"'
        )
        {
            return $true
        }
        return $false
    }

    #endregion
}
