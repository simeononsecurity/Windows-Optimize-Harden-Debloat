# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type WindowsFeatureRule

foreach ($rule in $rules)
{
    WindowsOptionalFeature (Get-ResourceTitle -Rule $rule)
    {
        Name   = $rule.Name
        Ensure = $rule.Ensure
    }
}
