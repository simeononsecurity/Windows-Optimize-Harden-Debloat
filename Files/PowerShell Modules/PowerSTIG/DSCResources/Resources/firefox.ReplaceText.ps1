# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = ($stig.RuleList | Select-Rule -Type FileContentRule).Where({ $PSItem.dscresource -eq 'ReplaceText' })

# Assert FireFox install directory

if (-not(Test-Path -Path $InstallDirectory))
{
    Write-Warning "$InstallDirectory not found. Verify FireFox is installed and the correct Install Directory is defined prior to starting DSC."
}

ReplaceText GeneralConfigFileName
{
    Path        = "$InstallDirectory\defaults\pref\autoconfig.js"
    Search      = 'pref\("general.config.filename", (.*)\);'
    Type        = 'Text'
    Text        = 'pref("general.config.filename", "firefox.cfg");'
    AllowAppend = $true
}

ReplaceText DoNotObscureFile
{
    Path        = "$InstallDirectory\defaults\pref\autoconfig.js"
    Search      = 'pref\("general.config.obscure_value", (.*)\);'
    Type        = 'Text'
    Text        = 'pref("general.config.obscure_value", 0);'
    AllowAppend = $true
}

<#
    The second file to create is called firefox.cfg and it is placed at the top level of the Firefox directory. It should always begin with a commented line, such as:
    // IMPORTANT: Start your code on the 2nd line
#>
ReplaceText BeginFileWithComment
{
    Path        = "$InstallDirectory\firefox.cfg"
    Search      = ('// FireFox preference file' + "`r")
    Type        = 'Text'
    Text        = ('// FireFox preference file' + "`r")
}

foreach ($rule in $rules)
{
    ReplaceText (Get-ResourceTitle -Rule $rule)
    {
        Path        = "$InstallDirectory\FireFox.cfg"
        Search      = 'lockPref\("{0}", (.*)\);' -f $rule.Key
        Type        = 'Text'
        Text        = 'lockPref("{0}", {1});' -f $rule.Key, (Format-FireFoxPreference -Value $rule.Value)
        AllowAppend = $true
    }
}
