# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VsphereAdvancedSettingsRule'

$advancedSettings = @{}
foreach ($rule in $rules)
{
    $key, $value = $rule.AdvancedSettings -split ' = '
    if ([string]::IsNullOrEmpty($key) -eq $false)
    {
        $advancedSettings.Add($key, $value)
    }
}

$resourceTitle = "[$($rules.id -join ' ')]"

VmHostAdvancedSettings $resourceTitle
{
    Name             = $HostIP
    Server           = $ServerIP
    Credential       = $Credential
    AdvancedSettings = $advancedSettings
}
