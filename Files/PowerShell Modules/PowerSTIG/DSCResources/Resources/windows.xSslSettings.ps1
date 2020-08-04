# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type SslSettingsRule

if ($rules)
{
    foreach ($website in $WebsiteName)
    {
        xSslSettings "[$($rules.id -join ' ')]$website"
        {
            Name     = $website
            Bindings = (Get-UniqueStringArray -InputObject $rules.Value)
        }
    }
}
