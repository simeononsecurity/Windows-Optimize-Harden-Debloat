# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereNtpSettingsRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose -Message "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a Vsphere Ntp Settings object.
    .DESCRIPTION
        The Vsphere Ntp Settings Rule class is used to extract the Vsphere Ntp settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere Ntp Settings rule, it is passed to the Vsphere Ntp Settings Rule class for parsing
        and validation.
#>
class VsphereNtpSettingsRuleConvert : VsphereNtpSettingsRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory.
    #>
    VsphereNtpSettingsRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule.
        .PARAMETER XccdfRule
            The STIG rule to convert.
    #>
    VsphereNtpSettingsRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        if ($this.IsOrganizationalSetting())
        {
            $this.SetOrganizationValueTestString()
        }

        $this.SetVsphereNtpSettings()
        $this.SetDscResource()
    }

    <#
        .SYNOPSIS
            Tests if and organizational value is required.
        .DESCRIPTION
            Tests if and organizational value is required.
    #>
    [bool] IsOrganizationalSetting ()
    {
        if ([String]::IsNullOrEmpty($this.NtpServer))
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
        Set the organizational value.
    .DESCRIPTION
        Extracts the organizational value from the key and then sets the value.
    #>
    [void] SetOrganizationValueTestString ()
    {
        $OrganizationValueTestString = Get-VsphereNtpSettingsOrganizationValueTestString -Id $this.id

        if (-not $this.SetStatus($OrganizationValueTestString))
        {
            $this.set_OrganizationValueTestString($OrganizationValueTestString)
            $this.set_OrganizationValueRequired($true)
        }
    }

    <#
        .SYNOPSIS
            Extracts the Vsphere NTP settings from the check-content and sets the value.
        .DESCRIPTION
            Gets the NTP server list from the xccdf content and sets the value.
            If the value that is returned is not valid, the parser status is
            set to fail.
    #>
    [void] SetVsphereNtpSettings ()
    {
        $vsphereNtpSettings = Get-VsphereNtpSettings -CheckContent $this.SplitCheckContent
        $this.set_NtpServer($vsphereNtpSettings)
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostNtpSettings'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'Get-VMHostNTPServer')
        {
            return $true
        }
        return $false
    }
}
