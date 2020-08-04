# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Returns the key and value properties for the STIG rule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-KeyValuePair
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    switch ( $checkContent )
    {
        { $PsItem -match 'Idle Time-out' }
        {
            $key = 'idleTimeout'
            $value = $null
        }
        { $PsItem -match 'Queue Length' }
        {
            $key = 'queueLength'
            $value = $null
        }
        { $PsItem -match 'Ping Enabled' }
        {
            $key = 'pingingEnabled'
            $value = '$true'
        }
        { $PsItem -match 'Rapid Fail Protection:Enabled' }
        {
            $key = 'rapidFailProtection'
            $value = '$true'
        }
        { $PsItem -match 'Failure Interval' }
        {
            $key = 'rapidFailProtectionInterval'
            $value = $null
        }
        { $PsItem -match 'Virtual Memory Limit' }
        {
            $key = 'restartMemoryLimit'
            $value = $null
        }
        { $PsItem -match 'Private Memory Limit' }
        {
            $key = 'restartPrivateMemoryLimit'
            $value = $null
        }
        { $PsItem -match 'Request Limit' }
        {
            $key = 'restartRequestsLimit'
            $value = $null
        }
        { $PsItem -match 'Generate Recycle Event Log Entry' }
        {
            $key = 'logEventOnRecycle'
            $value = "'Time,Schedule'"
        }
    }

    if ($null -ne $key)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Key: {0}, value: {1}" -f $key, $value)

        return @{
            key   = $key
            value = $value
        }
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No Key or Value found"
        return $null
    }
}

<#
    .SYNOPSIS
        Takes the key property from a WebAppPoolrule to determine the Organizational value
        test string to return.

    .PARAMETER Key
        Key property from the WebAppPoolrule.
#>
function Get-WebAppPoolOrganizationValueTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Key
    )

    # TO DO - This should not be a static list
    switch ( $Key )
    {
        { $PsItem -match 'idleTimeout' }
        {
            return "[TimeSpan]{0} -le [TimeSpan]'00:20:00' -and [TimeSpan]{0} -gt [TimeSpan]'00:00:00'"
        }
        { $PsItem -match 'queueLength' }
        {
            return "{0} -le 1000"
        }
        { $PsItem -match 'rapidFailProtectionInterval' }
        {
            return "[TimeSpan]{0} -le [TimeSpan]'00:05:00'"
        }
        { $PsItem -match 'restartMemoryLimit|restartPrivateMemoryLimit|restartRequestsLimit'}
        {
            return "{0} -ne 0"
        }
        default
        {
            return $null
        }
    }
}
#endregion
