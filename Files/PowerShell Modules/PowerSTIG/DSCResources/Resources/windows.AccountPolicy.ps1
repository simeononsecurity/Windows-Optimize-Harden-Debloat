# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type AccountPolicyRule

foreach ($rule in $rules)
{
    $policy = $rule.PolicyName -replace "(:)*\s","_"

    $scriptblock = [scriptblock]::Create("
        AccountPolicy '$(Get-ResourceTitle -Rule $rule)'
        {
            Name = '$policy'
            $policy = '$($rule.PolicyValue)'
        }"
    )

    $scriptblock.Invoke()
}
