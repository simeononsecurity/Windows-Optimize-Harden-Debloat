# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type WindowsFeatureRule

foreach ($rule in $rules)
{
    <#
        SMB1Protocol is referenced in many STIG's using the WindowsOptionalFeature
        cmdlet all server resources are processed with the WindowsFeature
        cmdlet, so the Feature name needs to be updated at compile time.
    #>
    if ($rule.Name -eq 'SMB1Protocol')
    {
        $rule.Name = 'FS-SMB1'
    }

    WindowsFeature (Get-ResourceTitle -Rule $rule)
    {
        Name   = $rule.Name
        Ensure = $rule.Ensure
    }
}
