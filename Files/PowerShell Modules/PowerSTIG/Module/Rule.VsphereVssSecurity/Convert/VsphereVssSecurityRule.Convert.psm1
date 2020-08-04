# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereVssSecurityRule.psm1

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
        Convert the contents of an xccdf check-content element into a Vsphere Vss Security Rule object
    .DESCRIPTION
        The VsphereVssSecurityRule class is used to extract the VsphereVssSecurityRule settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        VsphereVssSecurity rule, it is passed to the VsphereVssSecurityRule class for parsing
        and validation.
#>
class VsphereVssSecurityRuleConvert : VsphereVssSecurityRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    VsphereVssSecurityRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    VsphereVssSecurityRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $fixText = [VsphereVssSecurityRule]::GetFixText($XccdfRule)
        $this.SetVsphereForgedTransmits($fixText)
        $this.SetVsphereMacChanges($fixText)
        $this.SetVsphereAllowPromiscuous($fixText)
        $this.SetDscResource()
    }

    # Methods
    <#
    .SYNOPSIS
        Extracts the Vsphere ForgedTransmits settings from the fix text and sets the value
    .DESCRIPTION
        Gets the ForgedTransmits from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereForgedTransmits([string[]] $fixText)
    {
        $vsphereForgedTransmits = Get-VsphereForgedTransmits -FixText $fixText
        if (-not [String]::IsNullOrEmpty($vsphereForgedTransmits))
        {
            $this.set_ForgedTransmits($vsphereForgedTransmits)
        }
    }

    <#
    .SYNOPSIS
        Extracts the Vsphere MacChanges settings from the fix text and sets the value
    .DESCRIPTION
        Gets the MacChanges from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereMacChanges([string[]] $fixText)
    {
        $vsphereMacChange = Get-VsphereMacChange -FixText $fixText
        if (-not [String]::IsNullOrEmpty($vsphereMacChange))
        {
            $this.set_MacChanges($vsphereMacChange)
        }
    }

    <#
    .SYNOPSIS
        Extracts the Vsphere AllowPromiscuous settings from the fix text and sets the value
    .DESCRIPTION
        Gets the AllowPromiscuous from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereAllowPromiscuous([string[]] $fixText)
    {
        $vsphereAllowPromiscuous = Get-VsphereAllowPromiscuous -FixText $fixText
        if (-not [String]::IsNullOrEmpty($vsphereAllowPromiscuous))
        {
            $this.set_AllowPromiscuous($vsphereAllowPromiscuous)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostVssSecurity'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'Get-VirtualSwitch')
        {
            return $true
        }

        return $false
    }
}
