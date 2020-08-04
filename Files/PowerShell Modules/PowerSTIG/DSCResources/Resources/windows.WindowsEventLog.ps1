# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type WinEventLogRule

foreach ( $rule in $rules )
{
    WindowsEventLog (Get-ResourceTitle -Rule $rule)
    {
        LogName   = $rule.LogName
        IsEnabled = [boolean]$($rule.IsEnabled)
    }
}
