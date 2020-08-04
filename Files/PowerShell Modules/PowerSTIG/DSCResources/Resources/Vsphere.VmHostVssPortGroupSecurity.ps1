# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type 'VspherePortGroupSecurityRule'

foreach ($vm in $vmGroup)
{
    foreach ($rule in $rules)
    {
        if ($rule.AllowPromiscuous)
        {
            $allowPromiscuousInherited = $rule.AllowPromiscuousInherited
        }
        if ($rule.ForgedTransmits)
        {
            $forgedTransmitsInherited  = $rule.ForgedTransmitsInherited
        }
        if ($rule.MacChanges)
        {
            $macChangesInherited  = $rule.MacChangesInherited
        }

        $idValue += $rule.id
    }

    VmHostVssPortGroupSecurity "$vm-$idValue"
    {
        Name                      = $HostIP
        Server                    = $ServerIP
        Credential                = $Credential
        VmHostName                = $vm
        AllowPromiscuousInherited = [bool] $allowPromiscuousInherited
        ForgedTransmitsInherited  = [bool] $forgedTransmitsInherited
        MacChangesInherited       = [bool] $macChangesInherited
        Ensure                    = 'Present'
    }
}
