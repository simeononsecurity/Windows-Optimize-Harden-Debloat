# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type FileContentRule

foreach ($rule in $rules)
{
    if ($rule.Key -match "config")
    {
        $path = $ConfigPath
    }
    else
    {
        $path = $PropertiesPath
    }

    KeyValuePairFile "$(Get-ResourceTitle -Rule $rule)"
    {
        Path   = $path
        Name   = $rule.Key
        Ensure = 'Present'
        Text   = $rule.Value
    }
}
