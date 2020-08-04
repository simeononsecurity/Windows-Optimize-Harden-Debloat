# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type AuditSettingRule

foreach ( $rule in $rules )
{
    AuditSetting (Get-ResourceTitle -Rule $rule)
    {
        Query        = $rule.Query
        Property     = $rule.Property
        DesiredValue = $rule.DesiredValue
        Operator     = $rule.Operator
    }
}
