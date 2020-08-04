# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereSnmpAgentRule.psm1

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
        Convert the contents of an xccdf check-content element into a Vsphere object
    .DESCRIPTION
        The VsphereRule class is used to extract the Vsphere settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere rule, it is passed to the VsphereRule class for parsing
        and validation.
#>
class VsphereSnmpAgentRuleConvert : VsphereSnmpAgentRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    VsphereSnmpAgentRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    VsphereSnmpAgentRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $fixText = [VsphereSnmpAgentRule]::GetFixText($XccdfRule)
        $this.SetVsphereSnmpAgent($fixText)
        $this.SetDscResource()
    }

    # Methods
    <#
    .SYNOPSIS
        Extracts the Snmp Agent boolean from the check-content and sets the values
    .DESCRIPTION
        Gets the bollean from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereSnmpAgent ([string[]] $fixText)
    {
        $vsphereSnmpAgent = Get-VsphereSnmpAgent -FixText $fixText
        $this.set_Enabled($vsphereSnmpAgent)
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostSnmpAgent'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'Get-VMHostSnmp')
        {
            return $true
        }

        return $false
    }
}
