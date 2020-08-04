# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        Finds the Key property from a VsphereServiceRule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereServiceKey
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($CheckContent -match 'Get-VMHostService')
    {
        $name = ($CheckContent | Select-String -Pattern '(?<=Label -eq ")([^"]*)' -AllMatches).Matches.Value
    }

    switch ($name)
    {
        {$PSItem -match "NTP Daemon"}
        {
            $key = 'ntpd'
        }
        {$PSItem -match "ESXi Shell"}
        {
            $key = 'TSM'
        }
        {$PSItem -match "SSH"}
        {
            $key = 'TSM-SSH'
        }
    }

    if ($null -ne $key)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Key name: {0}" -f $key)
        return $key
    }
    else
    {
        return $null
    }
}

<#
    .SYNOPSIS
        Gets the startup policy and running status from a vsphere service rule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereServicePolicy
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($CheckContent -match 'Get-VMHostService')
    {
        $servicePolicy = ($CheckContent | Select-String -Pattern '(?<=verify it is )(\w+)' -AllMatches).Matches.Value

        if ($servicePolicy -eq "stopped")
        {
            $policy = "off"
            $running = $false
        }
        else
        {
            $policy = "Automatic"
            $running = $true
        }
    }

    if ($null -ne $policy)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Service Policy: {0}" -f $policy)
        return $policy,$running
    }
    else
    {
        return $null
    }
}
