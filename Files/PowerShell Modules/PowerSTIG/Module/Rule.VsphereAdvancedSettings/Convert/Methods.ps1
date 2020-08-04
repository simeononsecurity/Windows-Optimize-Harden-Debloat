# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        Takes the AdvancedSettings property from a VsphereAdvancedSettingsRule.

    .PARAMETER RawString
        An array of the raw string data taken from the Fix Text of the STIG.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereAdvancedSettings
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText,

        [Parameter()]
        [psobject]
        $CheckContent
    )

    if ($FixText -match 'Get-AdvancedSetting')
    {
        $matchName = ($FixText | Select-String -Pattern '(?<=Get-AdvancedSetting -Name )([^\s]+)' -AllMatches).Matches.Value
        $matchValue = ($FixText | Select-String -Pattern '(?<=Set-AdvancedSetting -Value |Set-AdvancedSetting -Value ")[^"]+' -AllMatches).Matches.Value
        $advancedSettings = "'{0}' = '{1}'" -f $matchName, $matchValue
    }

    switch ($matchName)
    {
        {$PSItem -eq "Annotations.WelcomeMessage"}
        {
            $matchValue = ($CheckContent | Select-String -Pattern 'You are accessing[^"]+(?<=details.)').Matches.Value
            $advancedSettings = "'{0}' = '{1}'" -f $matchName,$matchValue
        }
        {$PSItem -eq "Config.Etc.issue"}
        {
            $matchValue = ($CheckContent | Select-String -Pattern 'You are accessing[^"]+').Matches.Value
            $advancedSettings = "'{0}' = '{1}'" -f $matchName,$matchValue
        }
        {$PSItem -eq "Net.DVFilterBindIpAddress"}
        {
            $advancedSettings = "'{0}' = ''" -f $matchName
        }
        {$PSItem -match "Syslog.global.logHost|Config.HostAgent.plugins.hostsvc.esxAdminsGroup|Syslog.global.logDir"}
        {
            $advancedSettings = $null
        }
    }

    if ($null -ne $advancedSettings)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Advanced Setting: {0}" -f $advancedSettings)
        return $advancedSettings
    }
    else
    {
        return $null
    }
}

function Get-OrganizationValueTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    switch ($Id)
    {
        {$PsItem -match 'V-93955'}
        {
            return '{0} is set to "Syslog.global.logHost" = "site specific log host"'
        }
        {$PsItem -match 'V-94037'}
        {
            return '"{0}" is set to "Syslog.global.logDir" = "site specific log storage location"'
        }
        default
        {
            return $null
        }
    }
}
