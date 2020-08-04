# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Retrieves the Dns Server Windows event log name
#>
function Get-DnsServerWinEventLogName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter( Mandatory = $true)]
        [psobject]
        $StigString
    )

    # There is only one scenario to handle but we will use a switch to easily add additional scenarios
    switch ( $stigString )
    {
        { $stigString -match $regularExpression.WinEventLogPath }
        {
            $dnsServerWinEventLogName = 'Microsoft-Windows-DnsServer/Analytical'

            break
        }
        Default
        {
        }
    }

    return $dnsServerWinEventLogName
}
#endregion
