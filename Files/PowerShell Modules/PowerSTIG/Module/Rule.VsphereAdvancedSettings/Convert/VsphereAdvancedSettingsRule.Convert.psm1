# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereAdvancedSettingsRule.psm1

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
        The VsphereAdvancedSettingsRule class is used to extract the Vsphere settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere AdvancedSettings rule, it is passed to the VsphereRule class for parsing
        and validation.
#>
class VsphereAdvancedSettingsRuleConvert : VsphereAdvancedSettingsRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    VsphereAdvancedSettingsRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    VsphereAdvancedSettingsRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $fixText = [VsphereAdvancedSettingsRule]::GetFixText($XccdfRule)
        $this.SetVsphereAdvancedSettings($fixText)

        if ($this.IsOrganizationalSetting())
        {
            $this.SetOrganizationValueTestString()
        }

        $this.SetDscResource()
    }

    # Methods
    <#
    .SYNOPSIS
        Extracts the advanced settings key value pair from the check-content and sets the Advanced Setting
    .DESCRIPTION
        Gets the key value pair from the xccdf content and combines the two as a string.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereAdvancedSettings ([string[]] $fixText)
    {
        $vsphereAdvancedSettings = Get-VsphereAdvancedSettings -FixText $fixText -CheckContent $this.RawString
        $this.set_AdvancedSettings($vsphereAdvancedSettings)
    }

    <#
    .SYNOPSIS
        Tests if and organizational value is required
    .DESCRIPTION
        Tests if and organizational value is required
    #>
    [bool] IsOrganizationalSetting ()
    {
        if ($this.id -match 'V-93955|V-94025|V-94509|V-94533|V-94037')
        {
            return $true
        }
        else
        {
            return $false
        }
    }

    <#
    .SYNOPSIS
        Set the organizational value
    .DESCRIPTION
        Extracts the organizational value from the key and then sets the value
    #>
    [void] SetOrganizationValueTestString ()
    {
        $OrganizationValueTestString = Get-OrganizationValueTestString -Id $this.Id

        if (-not $this.SetStatus($OrganizationValueTestString))
        {
            $this.set_OrganizationValueTestString($OrganizationValueTestString)
            $this.set_OrganizationValueRequired($true)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostAdvancedSettings'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'Get-AdvancedSetting')
        {
            return $true
        }

        return $false
    }
}
