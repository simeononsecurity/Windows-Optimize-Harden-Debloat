# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions

<#
    .SYNOPSIS
        Takes the Name property from a VsphereAcceptanceLevelRule.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-VsphereAcceptanceLevel
{
    [CmdletBinding()]
    [OutputType([object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Fixtext
    )

    if ($Fixtext -match 'software.acceptance')
    {
        $acceptanceLevel = ($FixText | Select-String -Pattern '(?<=acceptance.Set\(")([^"]+)').Matches.Value
    }

    if ($null -ne $acceptanceLevel)
    {
        Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found Acceptance Level: {0}" -f $acceptanceLevel)
        return $acceptanceLevel
    }
    else
    {
        return $null
    }
}
