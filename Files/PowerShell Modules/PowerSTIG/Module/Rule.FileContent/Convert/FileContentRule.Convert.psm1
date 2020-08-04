# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\FileContentRule.psm1
using module .\FileContentType\FileContentType.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt', '*.psm1')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -File -Recurse -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}
# Header

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a fileContent object
    .DESCRIPTION
        The FileContentRule class is used to manage STIGs for applications that utilize a
        configuration file to manage security settings
#>
class FileContentRuleConvert : FileContentRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    FileContentRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a File Content Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    FileContentRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetKeyName()
        $this.SetValue()
        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the key name from the check-content and sets the value
        .DESCRIPTION
            Gets the key name from the xccdf content and sets the
            value. If the key name that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetKeyName ()
    {
        $thisKeyName = (Get-KeyValuePair $this.SplitCheckContent).Key

        if (-not $this.SetStatus($thisKeyName))
        {
            $this.set_Key($thisKeyName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the key value from the check-content and sets the value
        .DESCRIPTION
            Gets the key value from the xccdf content and sets the
            value. If the key value that is returned is not valid,
            the parser status is set to fail
    #>
    [void] SetValue ()
    {
        $thisValue = (Get-KeyValuePair $this.SplitCheckContent).Value

        if (-not $this.SetStatus($thisValue))
        {
            $this.set_Value($thisValue)
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            if ($this.Key -match 'deployment.')
            {
                $this.DscResource = 'KeyValuePairFile'
            }
            else
            {
                $this.DscResource = 'ReplaceText'
            }
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        $result = $false
        switch ( $true )
        {
            {
                (
                    $CheckContent -Match 'app.update.enabled' -and
                    $CheckContent -NotMatch 'Mozilla.cfg' -and
                    $CheckContent -NotMatch 'locked or'
                )
            }
            {
                $result = $false
                break
            }
            {
                (
                    $CheckContent -Match 'deployment.properties' -and
                    $CheckContent -Match '=' -and
                    $CheckContent -NotMatch 'exception.sites'
                ) -or
                (
                    $CheckContent -Match 'about:config' -and
                    $CheckContent -NotMatch 'Mozilla.cfg'
                )
            }
            {
                $result = $true
                break
            }
            default
            {
                $result = $false
                break
            }
        }
        return $result
    }

    <#
        .SYNOPSIS
            Tests if a rules contains more than one check
        .DESCRIPTION
            Gets the policy setting in the rule from the xccdf content and then
            checks for the existance of multiple entries.
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [bool] HasMultipleRules ([string] $CheckContent)
    {
        $keyValuePairs = Get-KeyValuePair -CheckContent ([FileContentRule]::SplitCheckContent($CheckContent))
        return (Test-MultipleFileContentRule -KeyValuePair $keyValuePairs)
    }

    <#
        .SYNOPSIS
            Splits the CheckContent into multiple CheckContent strings
        .DESCRIPTION
            When CheckContent is identified as containing multiple rules
            this method will break the CheckContent out into multiple
            CheckContent strings that contain single rules.
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    static [string[]] SplitMultipleRules ([string] $CheckContent)
    {
        return (Get-KeyValuePair -SplitCheckContent -CheckContent ([FileContentRule]::SplitCheckContent($CheckContent)))
    }
}
