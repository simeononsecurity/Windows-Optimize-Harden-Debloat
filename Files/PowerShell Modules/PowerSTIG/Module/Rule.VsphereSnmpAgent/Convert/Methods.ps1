# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        Gets the boolean SNMPAgent Enabled property from a VsphereSnmpAgentRule.

    .PARAMETER RawString
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereSnmpAgent
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $FixText
    )

    if ($FixText -match 'Get-VMHostSnmp')
    {
        $snmpAgent = ($FixText | Select-String -Pattern '(?<=Set-VMHostSnmp -Enabled\s)(.\w+)').Matches.Value
    }

    if ($null -ne $snmpAgent)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Host SNMP Enabled: {0}" -f $snmpAgent)
        return $snmpAgent
    }
    else
    {
        return $null
    }
}
