# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type SecurityOptionRule

foreach ($rule in $rules)
{
    $policy = $rule.OptionName -replace "(\/)|(:)*\s", "_"

    $scriptblock = ([scriptblock]::Create("
        SecurityOption  '$(Get-ResourceTitle -Rule $rule)'
        {
            Name = '$policy'
            $policy = '$($rule.OptionValue)'
        }")
    )

    $scriptblock.Invoke()
}
