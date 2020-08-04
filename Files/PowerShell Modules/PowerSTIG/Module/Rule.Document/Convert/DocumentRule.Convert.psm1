# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\DocumentRule.psm1

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
        Convert the contents of an xccdf check-content element into a document object
    .DESCRIPTION
        The DocumentRuleConvert class is used to extract the documentation requirements
        from the check-content of the xccdf. Once a STIG rule is identified as a
        document rule, it is passed to the DocumentRuleConvert class for parsing
        and validation.
#>
class DocumentRuleConvert : DocumentRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    DocumentRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Document Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    DocumentRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.DscResource = 'None'
    }

    <#
        .SYNOPSIS
            Converts an existing rule into a document rule
        .DESCRIPTION
            Provides a way to convert stig rules that have already been parsed
            into a document rule type. There are several instances where a STIG
            rule needs to be documented if configure a certain way.
        .PARAMETER RuleToConvert
            A STIG rule that has already been parsed.
    #>
    static [DocumentRule] ConvertFrom ([object] $RuleToConvert)
    {
        return [DocumentRule]::New($RuleToConvert.Id, $RuleToConvert.severity,
            $RuleToConvert.title, $RuleToConvert.rawString)
    }


    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match "Document(ation)?" -and
            $CheckContent -NotMatch "resourceSACL|Disk Management" -and
            $CheckContent -NotMatch "Caspol\.exe" -and
            $CheckContent -NotMatch "Examine the \.NET CLR configuration files" -and
            $CheckContent -NotMatch "\*\.exe\.config"
        )
        {
            return $true
        }
        return $false
    }
}
