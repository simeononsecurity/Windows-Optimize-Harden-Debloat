# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VsphereAcceptanceLevelRule'

foreach ($rule in $rules)
{
    VMHostAcceptanceLevel (Get-ResourceTitle -Rule $rule)
    {
        Name       = $HostIP
        Server     = $ServerIP
        Credential = $Credential
        Level      = $rule.Level
    }
}
