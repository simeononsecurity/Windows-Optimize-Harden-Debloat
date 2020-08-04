# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VsphereVssSecurityRule'

foreach ($virtualStandardSwitch in $virtualStandardSwitchGroup)
{
    foreach ($rule in $rules)
    {
        if ($rule.AllowPromiscuous)
        {
            $allowPromiscuous = $rule.AllowPromiscuous
        }
        if ($rule.ForgedTransmits)
        {
            $forgedTransmits = $rule.ForgedTransmits
        }
        if ($rule.MacChanges)
        {
            $macChanges = $rule.MacChanges
        }

        $idValue += $rule.id
    }

    VmHostVssSecurity "$virtualStandardSwitch-$idValue"
    {
        Name             = $HostIP
        Server           = $ServerIP
        Credential       = $Credential
        VssName          = $VirtualStandardSwitch
        AllowPromiscuous = [bool] $allowPromiscuous
        ForgedTransmits  = [bool] $forgedTransmits
        MacChanges       = [bool] $macChanges
        Ensure           = 'Present'
    }
}
