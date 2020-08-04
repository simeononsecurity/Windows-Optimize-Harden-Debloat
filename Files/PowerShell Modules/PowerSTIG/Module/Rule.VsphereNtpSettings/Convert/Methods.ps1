# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        This returns null for the value of a Vsphere Ntp SettingsRule, because the ony rule
        is an organizational setting.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereNtpSettings
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($CheckContent -match 'Get-VMHostNTPServer')
    {
        $ntpServer = $null
    }

    if ($null -ne $ntpServer)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] NTPServer List Found: {0}" -f $ntpServer)
        return $ntpServer
    }
    else
    {
        return $null
    }
}

<#
    .SYNOPSIS
        This returns the organizational test string from a Vsphere Ntp SettingsRule.

    .PARAMETER Id
        This is the id of the rule that matches the organizational test string.
#>
function Get-VsphereNtpSettingsOrganizationValueTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    if ($this.id -match "V-94039")
    {
        return '{0} is set to a string array of authoritative DoD time sources'
    }
}
