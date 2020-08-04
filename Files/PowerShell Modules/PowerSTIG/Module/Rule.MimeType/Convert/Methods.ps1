# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
.SYNOPSIS
    Returns the Extension for the STIG rule.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-Extension
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $mimeTypeMatch = $checkContent | Select-String -Pattern $regularExpression.mimeType

    return $mimeTypeMatch.matches.groups.value
}

<#
.SYNOPSIS
    Returns the MimeType for the STIG rule.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-MimeType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Extension
    )

    switch ( $Extension )
    {
        { $PsItem -match '\.exe|\.com' }
        {
            $mimeType = 'application/octet-stream'
        }
        { $PsItem -match '\.dll' }
        {
            $mimeType = 'application/x-msdownload'
        }
        { $PsItem -match '\.bat' }
        {
            $mimeType = 'application/x-bat'
        }
        { $PsItem -match '\.csh' }
        {
            $mimeType = 'application/x-csh'
        }
    }

    if ($null -ne $mimeType)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found MimeType: {0}" -f $mimeType)

        return $mimeType
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No MimeType found"
        return $null
    }
}

<#
.SYNOPSIS
    Returns the Extension for the STIG rule.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Get-Ensure
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if ($checkContent -match $regularExpression.mimeTypeAbsent)
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Ensure Absent"
        return "Absent"
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Ensure not found"
        return $null
    }
}

<#
.SYNOPSIS
    Tests to see if the stig rule needs to be split into multiples.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Test-MultipleMimeTypeRule
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $mimeTypes = $checkContent | Where-Object -FilterScript {$PSItem.startswith('.')}

    if ($mimeTypes.Count -gt 1)
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $true"
        return $true
    }
    else
    {
        Write-Verbose -message "[$($MyInvocation.MyCommand.Name)] : $false"
        return $false
    }
}

<#
.SYNOPSIS
    Splits a STIG setting into multiple rules when necessary.

.PARAMETER CheckContent
    An array of the raw string data taken from the STIG setting.
#>
function Split-MultipleMimeTypeRule
{
    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $splitMimeTypeRules = @()

    $mimeTypeMatches = $checkContent | Select-String -Pattern $regularExpression.mimeType

    $mimeTypes  = $mimeTypeMatches.matches.groups.value

    $baseCheckContent = $checkContent| Where-Object -Filterscript {$PSItem -notin $mimeTypes}

    foreach ($mimeType in $mimeTypes)
    {
        $rule = $baseCheckContent + $mimeType
        $splitMimeTypeRules += ($rule -join "`r`n")
    }

    return $splitMimeTypeRules
}
#endregion
