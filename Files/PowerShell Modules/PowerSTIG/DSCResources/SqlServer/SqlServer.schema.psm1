# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

using module ..\helper.psm1
using module ..\..\PowerStig.psm1

<#
    .SYNOPSIS
        A composite DSC resource to manage the SQL STIG settings.
    .PARAMETER SqlVersion
        The version of SQL being used E.g. 'Server2012'
    .PARAMETER SqlRole
        There are two STIGs that cover the scope of SQL. SQL Instance covers each instance of SQL on a server
        SQL Database covers each Database within an Instance.
    .PARAMETER StigVersion
        The version of the SQL STIG to apply and/or monitor
    .PARAMETER ServerInstance
        The name of the SQL Instance that the STIG data will be applied to.
        To define a specific Instance you must use the following format: "ComputerName\InstanceName"
        If you want to use the default instance, you only need to use the hosting computer name.
    .PARAMETER Database
        The Name of the database that you would like to be applied to. This parameter is only used
        for the SQL Database STIG.
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
configuration SqlServer
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $SqlVersion,

        [Parameter(Mandatory = $true)]
        [string]
        $SqlRole,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [version]
        $StigVersion,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $ServerInstance,

        [Parameter()]
        [ValidateNotNullOrEmpty()]
        [string[]]
        $Database,

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
    $stig = [STIG]::New('SqlServer', $SqlVersion, $SqlRole, $StigVersion)
    $stig.LoadRules($OrgSettings, $Exception, $SkipRule, $SkipRuleType)
    ##### END DO NOT MODIFY #####

    Import-DscResource -ModuleName SqlServerDsc -ModuleVersion 13.3.0
    . "$resourcePath\SqlServer.ScriptQuery.ps1"

    Import-DscResource -ModuleName SecurityPolicyDsc -ModuleVersion 2.4.0.0
    . "$resourcePath\Windows.SecurityOption.ps1"

    Import-DscResource -ModuleName AccessControlDsc -ModuleVersion 1.4.0.0
    . "$resourcePath\Windows.AccessControl.ps1"

    Import-DscResource -ModuleName PSDscResources -ModuleVersion 2.10.0.0
    . "$resourcePath\windows.Registry.ps1"
    . "$resourcePath\windows.Script.skip.ps1"
}
