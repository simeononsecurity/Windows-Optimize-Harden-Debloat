# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\AuditSettingRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a AuditSettingRule object
    .DESCRIPTION
        The AuditSettingRule class is used to extract the settings from rules that don't have
        and dedicated method of evaluation from the check-content of the xccdf.
        Once a STIG rule is identified as a AuditSetting rule, it is passed to the AuditSettingRule
        class for parsing and validation.

#>
class AuditSettingRuleConvert : AuditSettingRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    AuditSettingRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a AuditSetting Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    AuditSettingRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        switch ($this.rawString)
        {
            {$PSItem -Match "winver\.exe" }
            {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] Service Pack"
                $this.Query = 'SELECT * FROM Win32_OperatingSystem'
                $this.Property = 'Version'
                $this.Operator = '-le'

                $this.rawString -match "(?:Version\s*)(\d+(\.\d+)?)" | Out-Null

                $osMajMin = $matches[1]

                if ([int]$osMajMin -gt 6.3)
                {
                    [string]$osMajMin = '10.0'
                }

                $this.rawString -match "(?:Build\s*)(\d+)?" | Out-Null
                $osBuild = $matches[1]

                $this.DesiredValue = "$osMajMin.$osBuild"
                continue
            }
            {$PSItem -Match "Disk Management"}
            {
                Write-Verbose "[$($MyInvocation.MyCommand.Name)] File System Type"
                $this.Query = "SELECT * FROM Win32_LogicalDisk WHERE DriveType = '3'"
                $this.Property = 'FileSystem'
                $this.Operator = '-match'
                $this.DesiredValue = 'NTFS|ReFS'
            }
        }
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'AuditSetting'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match "Disk Management" -or
            $CheckContent -Match "winver\.exe"
        )
        {
            return $true
        }
        return $false
    }
}
