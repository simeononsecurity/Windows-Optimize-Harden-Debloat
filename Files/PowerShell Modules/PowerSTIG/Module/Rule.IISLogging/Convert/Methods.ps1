# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
.SYNOPSIS
    Returns the log format.

.Parameter CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-LogCustomFieldEntry
{
    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($checkContent -match $regularExpression.customFieldSection)
    {
        $customFieldEntries = @()
        [string[]] $customFieldMatch = $checkContent | Select-String -Pattern $regularExpression.customFields -AllMatches

        foreach ($customField in $customFieldMatch)
        {
            $customFieldEntry = ($customField -split $regularExpression.customFields).trim()
            $customFieldEntries += @{
                SourceType = $customFieldEntry[0] -replace ' ', ''
                SourceName = $customFieldEntry[1]
            }
        }
    }

    return $customFieldEntries
}

<#
.SYNOPSIS
    Returns the log flags.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-LogFlag
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $cleanCheckContent = $checkContent -replace ([RegularExpression]::excludeExtendedAscii), ''

    switch ($cleanCheckContent)
    {
        { $PSItem -match $regularExpression.logFlags }
        {
            $logFlagString = $cleanCheckContent | Select-String -Pattern $regularExpression.logFlags -AllMatches
            $logFlagValue = Get-LogFlagValue -LogFlags ($logFlagString.Matches.groups.value -split ',')
        }
        { $PSItem -match $regularExpression.standardFields }
        {
            [string] $logFlagLine = $cleanCheckContent | Select-String -Pattern $regularExpression.standardFields -AllMatches
            $logFlagString = $logFlagLine | Select-String -Pattern $regularExpression.standardFieldEntries -AllMatches
            $logFlagValue = Get-LogFlagValue -LogFlags ( $logFlagString.Matches.Groups.Where{$PSItem.name -eq 1}.value )
        }
    }

    return $logFlagValue
}

<#
.SYNOPSIS
    Returns the log format.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-LogFormat
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    [string] $logFormatLine = $checkContent | Select-String -Pattern $regularExpression.logFormat -AllMatches

    if (-not [String]::IsNullOrEmpty( $logFormatLine ))
    {
        $logFormat = $logFormatLine | Select-String -Pattern ([RegularExpression]::KeyValuePair) -AllMatches
        return $logFormat.Matches.Groups.value[-1]
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No log format found"
        return $null
    }
}

<#
.SYNOPSIS
    Returns the log roll over period.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-LogPeriod
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    switch ( $checkContent )
    {
        { $PsItem -match $regularExpression.logperiod }
        {
            return 'daily'
        }
    }
}

<#
.SYNOPSIS
    Returns the log event target.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-LogTargetW3C
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    [string] $logTargetW3cLine = $checkContent | Select-String -Pattern $regularExpression.logtargetw3c -AllMatches

    if (-not [String]::IsNullOrEmpty( $logTargetW3cLine ))
    {
        $logTargetW3C = $logTargetW3cLine | Select-String -Pattern ([RegularExpression]::KeyValuePair) -AllMatches

        switch ( $logTargetW3C.Matches.Groups.value )
        {
            { $PSItem -match 'Both log file and ETW event'}
            {
                return 'File,ETW'
            }
        }
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No log event target found"
        return $null
    }
}

<#
.SYNOPSIS
    Translates and returns the log flag constants

.PARAMETER LogFlags
    Array of log flags
#>
function Get-LogFlagValue
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $LogFlags
    )

    $logFlagReturn = @()

    foreach ($flag in $LogFlags)
    {
        $logFlagReturn += $logflagsConstant.($flag.trim())
    }

    return $logFlagReturn.where{ -not [string]::IsNullOrEmpty($PSItem) } -join ','
}
#endregion
