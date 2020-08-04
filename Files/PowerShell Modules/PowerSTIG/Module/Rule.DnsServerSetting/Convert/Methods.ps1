# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Retrieves the DNS server property setting
#>
function Get-DnsServerSettingProperty
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    # There is only one scenario to handle but we will use a switch to easily add additional scenarios
    switch ( $checkContent )
    {
        { $checkContent -match $regularExpression.textBetweenTheTab }
        {
            $patternMatch = $checkContent | Select-String -Pattern $regularExpression.textBetweenTheTab
            $dnsServerPropertyName = ($patternMatch.Matches.groups[-1].Value -replace $regularExpression.nonLetters).Trim()
            $dnsServerPropertyName = $Script:DnsServerSetting[$dnsServerPropertyName]

            break
        }
        Default
        {
        }
    }

    return $dnsServerPropertyName
}

<#
    .SYNOPSIS
        Retrieves the Dns Server Setting Property Value
#>
function Get-DnsServerSettingPropertyValue
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true)]
        [string[]]
        $CheckContent
    )

    $MyCommand = $MyInvocation.MyCommand.Name

    Write-Verbose "[$MyCommand]"

    switch ( $checkContent )
    {
        { $checkContent -match $regularExpression.allEvents}
        {
            # 4 equals all events
            $dnsServerSettingPropertyValue = 4

            break
        }

        default
        {
            $dnsServerSettingPropertyValue = '$True'
        }
    }

    return $dnsServerSettingPropertyValue
}
#endregion
