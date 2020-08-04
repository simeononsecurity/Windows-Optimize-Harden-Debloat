# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

using module ..\helper.psm1
using module ..\..\PowerStig.psm1

<#
    .SYNOPSIS
        A composite DSC resource to manage the Windows Server STIG settings
    .PARAMETER OsVersion
        The version of the server operating system STIG to apply and monitor
    .PARAMETER OsRole
        The role of the server operating system STIG to apply and monitor. This value further
        filters the OsVersion to select the exact STIG to apply
    .PARAMETER StigVersion
        Uses the OsVersion and OsRole to select the version of the STIG to apply and monitor. If
        this parameter is not provided, the most recent version of the STIG is automatically selected.
    .PARAMETER ForestName
        A string that sets the forest name for items such as security group. The input should be the FQDN of the forest.
        If this is omitted the forest name of the computer that generates the configuration will be used.
    .PARAMETER DomainName
        A string that sets the domain name for items such as security group. The input should be the FQDN of the domain.
        If this is omitted the domain name of the computer that generates the configuration will be used.
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
configuration WindowsServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $OsVersion,

        [Parameter(Mandatory = $true)]
        [string]
        $OsRole,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [version]
        $StigVersion,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $ForestName,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string]
        $DomainName,

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
    $stig = [STIG]::New('WindowsServer', $OsVersion, $OsRole, $StigVersion)
    $stig.LoadRules($OrgSettings, $Exception, $SkipRule, $SkipRuleType)
    ##### END DO NOT MODIFY #####

    Import-DscResource -ModuleName AccessControlDsc -ModuleVersion 1.4.0.0
    . "$resourcePath\windows.AccessControl.ps1"

    Import-DscResource -ModuleName AuditPolicyDsc -ModuleVersion 1.2.0.0
    . "$resourcePath\windows.AuditPolicySubcategory.ps1"

    Import-DscResource -ModuleName GPRegistryPolicyDsc -ModuleVersion 1.2.0
    Import-DscResource -ModuleName PSDscResources -ModuleVersion 2.10.0.0
    . "$resourcePath\windows.Registry.ps1"
    . "$resourcePath\windows.Script.skip.ps1"
    . "$resourcePath\windows.Service.ps1"
    . "$resourcePath\windows.WindowsFeature.ps1"

    Import-DscResource -ModuleName WindowsDefenderDSC -ModuleVersion 1.0.0.0
    . "$resourcePath\windows.ProcessMitigation.ps1"

    Import-DscResource -ModuleName SecurityPolicyDsc -ModuleVersion 2.4.0.0
    . "$resourcePath\windows.AccountPolicy.ps1"
    . "$resourcePath\windows.UserRightsAssignment.ps1"
    . "$resourcePath\windows.SecurityOption.ps1"

    Import-DscResource -ModuleName AuditSystemDsc -ModuleVersion 1.1.0
    . "$resourcePath\windows.AuditSetting.ps1"

    . "$resourcePath\windows.RefreshRegistryPolicy.ps1"
}
