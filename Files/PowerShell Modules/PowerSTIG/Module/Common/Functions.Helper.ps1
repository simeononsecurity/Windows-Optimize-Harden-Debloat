# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# Header

<#
    .SYNOPSIS
        Converts OrgSetting Xml object to a hashtable

    .DESCRIPTION
        Converts OrgSetting Xml object to a hashtable. The hashtable can be used to merge
        settings from the default xml and user specified settings passed from the configuration

    .PARAMETER XmlOrgSetting
        Xml object OrgSettings from the org.default.xml file

    .EXAMPLE
        PS C:\> [xml]$xmlOrgSettings = (Get-Content -Path ($this.RuleFile -replace '.xml', '.org.default.xml'))
        PS C:\> $settings = ConvertTo-OrgSettingHashtable -XmlOrgSetting $xmlOrgSettings

        This example will set the xmlOrgSettings variable as an xml object, representing the contents of
        the technology specific org.default.xml file. Pass the xmlOrgSettings object to the XmlOrgSetting parameter
        in order to convert the xml object to a hashtable.
#>

function ConvertTo-OrgSettingHashtable
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [xml]
        $XmlOrgSetting
    )

    $result = @{}
    foreach ($ruleId in $XmlOrgSetting.OrganizationalSettings.OrganizationalSetting)
    {
        $ruleIdValues = @{}
        $ruleIdProperty = $ruleId.Attributes.Name | Where-Object -FilterScript {$PSItem -ne 'id'}
        foreach ($property in $ruleIdProperty)
        {
            $ruleIdValues.Add($property, ($ruleId.GetAttribute($property)))
        }
        $result.Add($ruleId.id, $ruleIdValues)
    }

    return $result
}

<#
    .SYNOPSIS
        Merges Default OrgSettings with user specified OrgSettings at configuration run time.

    .DESCRIPTION
        Merges Default OrgSettings with user specified OrgSettings at configuration run time.

    .PARAMETER DefaultOrgSetting
        Hashtable representing the contents of the org.default.xml file.

    .PARAMETER UserSpecifiedOrgSetting
        Hashtable representing data passed from the configuration by the user.

    .EXAMPLE
        PS C:\> [xml]$xmlOrgSettings = (Get-Content -Path ($this.RuleFile -replace '.xml', '.org.default.xml'))
        PS C:\> $settings = ConvertTo-OrgSettingHashtable -XmlOrgSetting $xmlOrgSettings
        PS C:\> $orgSettings = Merge-OrgSettingValue -DefaultOrgSetting $settings -UserSpecifiedOrgSetting $OrgSettings

        This example will take an xml OrgSettings file, convert it to a hashtable, then merge the contents to user
        specified OrgSettings passed during configuration.
#>

function Merge-OrgSettingValue
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [hashtable]
        $DefaultOrgSetting,

        [Parameter(Mandatory = $true)]
        [hashtable]
        $UserSpecifiedOrgSetting
    )

    foreach ($ruleId in $UserSpecifiedOrgSetting.Keys)
    {
        $DefaultOrgSetting[$ruleId] = $UserSpecifiedOrgSetting[$ruleId]
    }

    return $DefaultOrgSetting
}
