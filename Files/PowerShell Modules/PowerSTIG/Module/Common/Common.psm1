# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#region Enum
<#
    STIGS have an associated severity that determines the impact of the finding if it
    is not configured properly
#>
enum severity
{
    low
    medium
    high
}

<#
    The status enum is used to display the status of the STIG item processing
#>
enum status
{
    pass
    warn
    fail
}

<#
    The process enum is used as a flag for further automation. The intent is that if a STIG
    has been fully processed, then the setting can be automatically published to a server. If
    a setting has not been fully processed then it needs to be manually processed. This is
    different from the status enum in that status is a control flag to describe the state
    of the item processing
#>
enum process
{
    auto
    manual
}

enum ensure
{
    Present
    Absent
}

#endregion

#region RegexClass

class RegularExpression
{
    static [string[]] $TextBetweenQuotes = '["''](.*?)["'']'
    static [bool] MatchTextBetweenQuotes([string] $string)
    {
        return $string -Match [RegularExpression]::TextBetweenQuotes
    }

    static [string[]] $TextBetweenParentheses = '\(([^\)]+)\)'
    static [bool] MatchTextBetweenParentheses([string] $string)
    {
        return $string -Match [RegularExpression]::TextBetweenParentheses
    }

    static [string[]] $CustomFieldSection = 'Under "Custom Fields", verify the following fields'
    static [bool] MatchCustomFieldSection([string] $string)
    {
        return $string -Match [RegularExpression]::CustomFieldSection
    }

    static [string[]] $ExcludeExtendedAscii = '[^\x20-\x7A]+'
    static [bool] MatchExcludeExtendedAscii([string] $string)
    {
        return $string -Match [RegularExpression]::ExcludeExtendedAscii
    }

    static [string[]] $KeyValuePair = '(?<=\").+?(?=\")'
    static [bool] MatchKeyValuePair([string] $string)
    {
        return $string -Match [RegularExpression]::KeyValuePair
    }
}
#endregion

foreach ($supportFile in (Get-ChildItem -Path $PSScriptRoot -Recurse -File -Exclude $MyInvocation.MyCommand.Name))
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}

Export-ModuleMember -Function '*' -Variable '*'
