# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type AuditPolicyRule

foreach ( $rule in $rules )
{
    AuditPolicySubcategory (Get-ResourceTitle -Rule $rule)
    {
        Name      = $rule.Subcategory
        AuditFlag = $rule.AuditFlag
        Ensure    = $rule.Ensure
    }
}
