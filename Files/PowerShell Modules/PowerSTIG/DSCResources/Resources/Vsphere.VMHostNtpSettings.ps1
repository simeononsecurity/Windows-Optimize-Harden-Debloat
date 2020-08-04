# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VsphereNtpSettingsRule'

foreach ($rule in $rules)
{
    VmHostNtpSettings (Get-ResourceTitle -Rule $rule)
    {
        Name       = $HostIP
        Server     = $ServerIP
        Credential = $Credential
        NtpServer  = $rule.NtpServer
    }
}
