# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\DnsServerRootHintRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -File -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into an Dns Server
        Root Hint object
    .DESCRIPTION
        The DnsServerRootHintRule class is used to extract the Dns Server Root Hints
        from the check-content of the xccdf. Once a STIG rule is identified as a
        DnsServerRootHint, it is passed to the DnsServerRootHintRule class for
        parsing and validation.
    .PARAMETER HostName
        The host name of the root hint server
    .PARAMETER IpAddress
        The ip address of the root hint server
#>
class DnsServerRootHintRuleConvert : DnsServerRootHintRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    DnsServerRootHintRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Dns Server Root Hint Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    DnsServerRootHintRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.set_HostName('$null')
        $this.set_IpAddress('$null')
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'Script'
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
            $CheckContent -Match 'dnsmgmt\.msc' -and
            $CheckContent -Match 'Verify the \"root hints\"'
        )
        {
            return $true
        }
        return $false
    }
}
