# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VsphereKernelActiveDumpPartitionRule'

foreach ($rule in $rules)
{
    VmHostVMKernelActiveDumpPartition (Get-ResourceTitle -Rule $rule)
    {
        Name       = $HostIP
        Server     = $ServerIP
        Credential = $Credential
        Enable     = [bool] $rule.Enabled
    }
}
