# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Parses the rawString from the rule to retrieve the Key name and Value
        for OracleJRE STIGs
    .DESCRIPTION
        The FileContentType is used to extend filter and parse logic for different 
        FileContentRules without modifing existing filtering and parsing logic
    .PARAMETER MatchResult
        The list of items to filter and parse
#>
function Get-FilteredItem
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [psobject]
        $MatchResult
    )

        $lineResult = $matchResult.Matches | Where-Object -FilterScript {$PSItem.Value -match '=' -or $PSItem.Value -match '.locked' -or $PSItem.Value -match '.mandatory'}
        if ($lineResult)
        {
            return Get-ParsedItem -LineResult $lineResult
        }
        else
        {
            return $null
        }
}

<#
    .SYNOPSIS
        Applies the specific parsing strategy for a specific FileContentType
    .DESCRIPTION
        The FileContentType is used to extend filter and parse logic for different 
        FileContentRules without modifing existing filtering and parsing logic
    .PARAMETER LineResult
        The specific line item to parse
#>
function Get-ParsedItem
{
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [AllowEmptyString()]
        [psobject]
        $LineResult
    )
    
    $setting = @()
    $settingNoQuotes = $lineResult[0].Value -replace $regexToRemove, ""
    if ($lineResult[0].Value -match '=')
    {
        $setting = $settingNoQuotes.Split('=') | ForEach-Object {
            New-Object PSObject -Property @{Value=$_}
        }
    }

    if ($lineResult[0].Value -match '.locked' -or $lineResult[0].Value -match '.mandatory')
    {
        $setting = @($settingNoQuotes, 'true') | ForEach-Object {
            New-Object PSObject -Property @{Value=$_}
        }
    }
    return $setting
}
