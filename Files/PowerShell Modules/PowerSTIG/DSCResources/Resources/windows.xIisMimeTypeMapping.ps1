# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type MimeTypeRule

if ($WebsiteName)
{
    foreach ($website in $WebsiteName)
    {
        foreach ($rule in $rules)
        {
            xIisMimeTypeMapping "$(Get-ResourceTitle -Rule $rule -Instance $website)"
            {
                ConfigurationPath = "IIS:\Sites\$website"
                Extension         = $rule.Extension
                MimeType          = $rule.MimeType
                Ensure            = $rule.Ensure
            }
        }
    }
}
else
{
    foreach ($rule in $rules)
    {
        xIisMimeTypeMapping "$(Get-ResourceTitle -Rule $rule)"
        {
            ConfigurationPath = "MACHINE/WEBROOT/APPHOST"
            Extension         = $rule.Extension
            MimeType          = $rule.MimeType
            Ensure            = $rule.Ensure
        }
    }
}
