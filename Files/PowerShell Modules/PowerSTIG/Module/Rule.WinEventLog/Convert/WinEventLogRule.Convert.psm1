# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\WinEventLogRule.psm1

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
        Convert the contents of an xccdf check-content element into a
        WinEventLogRuleConvert object
    .DESCRIPTION
        The WinEventLogRuleConvert class is used to extract the windows event log settings
        from the check-content of the xccdf. Once a STIG rule is identified as a
        windows event log rule, it is passed to the WinEventLogRuleConvert class for
        parsing and validation.

#>
class WinEventLogRuleConvert : WinEventLogRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    WinEventLogRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a Win EventLog Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    WinEventLogRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetWinEventLogName()
        $this.SetWinEventLogIsEnabled()
        $this.SetDuplicateRule()
        if ($this.IsExistingRule($global:stigSettings))
        {
            $newId = Get-AvailableId -Id $XccdfRule.id
            $this.set_id($newId)
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the event log from the check-content and sets the value
        .DESCRIPTION
            Gets the event log from the xccdf content and sets the value. If
            the name that is returned is not valid, the parser status is set
            to fail.
    #>
    [void] SetWinEventLogName ()
    {
        $thisDnsWinEventLogName = Get-DnsServerWinEventLogName -StigString $this.SplitCheckContent

        if (-not $this.SetStatus($thisDnsWinEventLogName))
        {
            $this.set_LogName($thisDnsWinEventLogName)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'xWinEventLog'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    <#
        .SYNOPSIS
            Extracts the event log enabled status from the check-content and
            sets the value
        .DESCRIPTION
            Gets the event log enabled status from the xccdf content and sets the
            value. If the enabled status that is returned is not valid, the
            parser status is set to fail.
    #>
    [void] SetWinEventLogIsEnabled ()
    {
        # The DNS STIG always sets this to true
        $this.IsEnabled = $true
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match 'Logs\\Microsoft' -and
            $CheckContent -Match 'eventvwr\.msc'
        )
        {
            return $true
        }
        return $false
    }
    #endregion
}
