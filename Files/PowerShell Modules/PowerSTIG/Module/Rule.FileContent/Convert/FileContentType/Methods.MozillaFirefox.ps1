# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Parses the rawString from the rule to retrieve the Key name and Value
        for MozillaFirefox STIGs
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

    $lineResult = $matchResult.Matches -notmatch 'about:config'
    if ($lineResult)
    {
        return $lineResult
    }
    else
    {
        return $null
    }
}
