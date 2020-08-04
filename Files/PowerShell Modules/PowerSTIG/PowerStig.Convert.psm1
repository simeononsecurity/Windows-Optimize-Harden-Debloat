# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#Requires -Version 5.1

<#
    The order of the dot sourced files is important due to the way that PowerShell processes the
    files (Top/Down). The Classes in the module depend on the enumerations, so if you want to
    alphabetize this list, don't. PowerShell with throw an error indicating that the enumerations
    can't be found, if you try to load the classes before the enumerations.
#>
using module .\Module\Common\Common.psm1
using module .\Module\Rule\Rule.psm1
using module .\Module\Rule\Convert\ConvertFactory.psm1
using module .\Module\Rule.AccountPolicy\Convert\AccountPolicyRule.Convert.psm1
using module .\Module\Rule.AuditPolicy\Convert\AuditPolicyRule.Convert.psm1
using module .\Module\Rule.DnsServerRootHint\Convert\DnsServerRootHintRule.Convert.psm1
using module .\Module\Rule.DnsServerSetting\Convert\DnsServerSettingRule.Convert.psm1
using module .\Module\Rule.Document\Convert\DocumentRule.Convert.psm1
using module .\Module\Rule.FileContent\Convert\FileContentRule.Convert.psm1
using module .\Module\Rule.Group\Convert\GroupRule.Convert.psm1
using module .\Module\Rule.IISLogging\Convert\IISLoggingRule.Convert.psm1
using module .\Module\Rule.Manual\Convert\ManualRule.Convert.psm1
using module .\Module\Rule.MimeType\Convert\MimeTypeRule.Convert.psm1
using module .\Module\Rule.Permission\Convert\PermissionRule.Convert.psm1
using module .\Module\Rule.ProcessMitigation\Convert\ProcessMitigationRule.Convert.psm1
using module .\Module\Rule.Registry\Convert\RegistryRule.Convert.psm1
using module .\Module\Rule.SecurityOption\Convert\SecurityOptionRule.Convert.psm1
using module .\Module\Rule.Service\Convert\ServiceRule.Convert.psm1
using module .\Module\Rule.SqlScriptQuery\Convert\SqlScriptQueryRule.Convert.psm1
using module .\Module\Rule.UserRight\Convert\UserRightRule.Convert.psm1
using module .\Module\Rule.WebAppPool\Convert\WebAppPoolRule.Convert.psm1
using module .\Module\Rule.WebConfigurationProperty\Convert\WebConfigurationPropertyRule.Convert.psm1
using module .\Module\Rule.WindowsFeature\Convert\WindowsFeatureRule.Convert.psm1
using module .\Module\Rule.WinEventLog\Convert\WinEventLogRule.Convert.psm1
using module .\Module\Rule.SslSettings\Convert\SslSettingsRule.Convert.psm1
using module .\Module\Rule.AuditSetting\Convert\AuditSettingRule.Convert.psm1
using module .\Module\Rule.VsphereAdvancedSettings\Convert\VsphereAdvancedSettingsRule.Convert.psm1
using module .\Module\Rule.VsphereService\Convert\VsphereServiceRule.Convert.psm1
using module .\Module\Rule.VspherePortGroupSecurity\Convert\VspherePortGroupSecurityRule.Convert.psm1
using module .\Module\Rule.VsphereAcceptanceLevel\Convert\VsphereAcceptanceLevelRule.Convert.psm1
using module .\Module\Rule.VsphereSnmpAgent\Convert\VsphereSnmpAgentRule.Convert.psm1
using module .\Module\Rule.VsphereKernelActiveDumpPartition\Convert\VsphereKernelActiveDumpPartitionRule.Convert.psm1
using module .\Module\Rule.VsphereNtpSettings\Convert\VsphereNtpSettingsRule.Convert.psm1
using module .\Module\Rule.VsphereVssSecurity\Convert\VsphereVssSecurityRule.Convert.psm1

# load the public functions
foreach ($supportFile in ( Get-ChildItem -Path "$PSScriptRoot\Module\Stig\Convert" -Recurse -Filter '*.ps1' -Exclude 'Data.*.ps1' ) )
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}

Export-ModuleMember -Function @(
    'ConvertFrom-StigXccdf',
    'ConvertTo-PowerStigXml',
    'Compare-PowerStigXml',
    'Get-ConversionReport',
    'Split-StigXccdf',
    'Get-HardCodedRuleLogFileEntry'
)
