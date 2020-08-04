# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type DnsServerRootHintRule

foreach ($rule in $rules)
{
    Script (Get-ResourceTitle -Rule $rule)
    {
        SetScript =
        {
            Get-DnsServerRootHint | Where-Object {$_.NameServer.RecordData.NameServer -like "*.Root-Servers.net."} | Remove-DnsServerRootHint
        }

        TestScript =
        {
            $result = $false
            $targetResource = Get-DnsServerRootHint | Where-Object {$_.NameServer.RecordData.NameServer -like "*.Root-Servers.net."}
            if ($null -eq $targetResource)
            {
                $result = $true
            }

            Return $result
        }

        GetScript =
        {
            $returnString = $null
            foreach ($rootHint in (Get-DnsServerRootHint))
            {
                $returnString += $rootHint.ipaddress.hostName + ";"
            }

            Return @{Result = $returnString}
        }
    }
}
