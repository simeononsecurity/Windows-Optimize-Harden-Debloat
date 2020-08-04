# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\MimeTypeRule.psm1

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
        Convert the contents of an xccdf check-content element into a mime type object
    .DESCRIPTION
        The MimeTypeRule class is used to extract mime types from the
        check-content of the xccdf. Once a STIG rule is identifed as an
        mime type rule, it is passed to the MimeTypeRule class for parsing
        and validation.

#>
class MimeTypeRuleConvert : MimeTypeRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    MimeTypeRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Mime Type Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    MimeTypeRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetExtension()
        $this.SetMimeType()
        $this.SetEnsure()
        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the extension name from the check-content and sets the value
        .DESCRIPTION
            Gets the extension name from the xccdf content and sets the value.
            If the extension name that is returned is not valid, the parser
            status is set to fail
    #>
    [void] SetExtension ()
    {
        $thisExtension = Get-Extension -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisExtension))
        {
            $this.set_Extension($thisExtension)
        }
    }

    <#
        .SYNOPSIS
            Extracts the mime type from the check-content and sets the value
        .DESCRIPTION
            Gets the mime type from the xccdf content and sets the value.
            If the mime type that is returned is not valid, the parser
            status is set to fail
    #>
    [void] SetMimeType ()
    {
        $thisMimeType = Get-MimeType -Extension $this.Extension

        if (-not $this.SetStatus($thisMimeType))
        {
            $this.set_MimeType($thisMimeType)
        }
    }

    <#
        .SYNOPSIS
            Sets the ensure flag to the provided value
        .DESCRIPTION
            Sets the ensure flag to the provided value
    #>
    [void] SetEnsure ()
    {
        $thisEnsure = Get-Ensure -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisEnsure))
        {
            $this.set_Ensure($thisEnsure)
        }
    }

    <#
        .SYNOPSIS
            Tests if a rule contains multiple checks
        .DESCRIPTION
            Search the rule text to determine if multiple mime types are defined
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    <#{TODO}#> # HasMultipleRules is implemented inconsistently.
    static [bool] HasMultipleRules ([string] $CheckContent)
    {
        return Test-MultipleMimeTypeRule -CheckContent ([MimeTypeRule]::SplitCheckContent($CheckContent))
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. This method splits a mime type into multiple rules. Each
            split rule id is appended with a dot and letter to keep reporting
            per the ID consistent. An example would be is V-1000 contained 2
            checks, then SplitMultipleRules would return 2 objects with rule ids
            V-1000.a and V-1000.b
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>

    static [string[]] SplitMultipleRules ([string] $CheckContent)
    {
        return (Split-MultipleMimeTypeRule -CheckContent ([MimeTypeRule]::SplitCheckContent($CheckContent)))
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'xIisMimeTypeMapping'
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
            $CheckContent -Match 'MIME Types' -and
            $CheckContent -Match 'IIS 8\.5|IIS 10\.0'
        )
        {
            return $true
        }
        return $false
    }
    #endregion
}
