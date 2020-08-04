# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type DnsServerSettingRule

foreach ( $rule in $rules )
{
    $scriptblock = ([scriptblock]::Create("
        xDnsServerSetting  '$(Get-ResourceTitle -Rule $rule)'
        {
            Name = '$($rule.PropertyName)'
            $($rule.PropertyName)  = $($rule.PropertyValue)
        }")
    )

    $scriptblock.Invoke()
}
