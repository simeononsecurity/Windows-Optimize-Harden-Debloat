#region Header
using module ..\helper.psm1
using module ..\..\PowerStig.psm1
#endregion Header

#region Composite

<#
    .SYNOPSIS
        A composite DSC resource to manage the IIS Site STIG settings
    .PARAMETER IisVersion
        The version of the IIS Stig to apply
    .PARAMETER WebsiteName
        Array of website names used for MimeTypeRule, WebConfigurationPropertyRule, and IisLoggingRule.
    .PARAMETER WebAppPool
        Array of web application pool names used for WebAppPoolRule
    .PARAMETER StigVersion
        The version of the IIS Site STIG version to apply and monitor
    .PARAMETER Exception
        A hashtable of StigId=Value key pairs that are injected into the STIG data and applied to
        the target node. The title of STIG settings are tagged with the text 'Exception' to identify
        the exceptions to policy across the data center when you centralize DSC log collection.
    .PARAMETER OrgSettings
        The path to the xml file that contains the local organizations preferred settings for STIG
        items that have allowable ranges.  The OrgSettings parameter also accepts a hashtable for
        values that need to be modified.  When a hashtable is used, the specified values take
        presidence over the values defined in the org.default.xml file.
    .PARAMETER SkipRule
        The SkipRule Node is injected into the STIG data and applied to the taget node. The title
        of STIG settings are tagged with the text 'Skip' to identify the skips to policy across the
        data center when you centralize DSC log collection.
    .PARAMETER SkipRuleType
        All STIG rule IDs of the specified type are collected in an array and passed to the Skip-Rule
        function. Each rule follows the same process as the SkipRule parameter.
#>
configuration IisSite
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [version]
        $IisVersion,

        [Parameter(Mandatory = $true)]
        [string[]]
        $WebsiteName,

        [Parameter()]
        [string[]]
        $WebAppPool,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [version]
        $StigVersion,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [hashtable]
        $Exception,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [object]
        $OrgSettings,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $SkipRule,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $SkipRuleType
    )

    ##### BEGIN DO NOT MODIFY #####
    $stig = [STIG]::New('IISSite', $IisVersion, $StigVersion)
    $stig.LoadRules($OrgSettings, $Exception, $SkipRule, $SkipRuleType)
    ##### END DO NOT MODIFY #####

    Import-DscResource -ModuleName PSDscResources -ModuleVersion 2.10.0.0
    . "$resourcePath\windows.Script.skip.ps1"
    . "$resourcePath\windows.WindowsFeature.ps1"

    Import-DscResource -ModuleName xWebAdministration -ModuleVersion 2.5.0.0
    . "$resourcePath\windows.xWebSite.ps1"
    . "$resourcePath\windows.xWebAppPool.ps1"
    . "$resourcePath\windows.xIisMimeTypeMapping.ps1"
    . "$resourcePath\windows.xWebConfigProperty.ps1"
    . "$resourcePath\windows.xSslSettings.ps1"
}

#endregion Composite
