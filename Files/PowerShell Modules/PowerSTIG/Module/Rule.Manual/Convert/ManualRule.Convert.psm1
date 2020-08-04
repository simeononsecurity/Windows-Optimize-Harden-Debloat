# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\ManualRule.psm1

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
        Convert the contents of an xccdf check-content element into a Manual check object
    .DESCRIPTION
        The ManualRule class is used to extract the manual checks from the
        check-content of the xccdf. Once a STIG rule is identifed as a manual
        rule, it is passed to the ManualRule class for parsing and validation.
#>
class ManualRuleConvert : ManualRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    ManualRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Manual Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    ManualRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.DscResource = 'None'
    }
}
