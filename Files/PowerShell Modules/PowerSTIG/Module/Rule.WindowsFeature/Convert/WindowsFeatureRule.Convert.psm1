# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\WindowsFeatureRule.psm1

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
        Convert the contents of an xccdf check-content element into a windows
        feature object
    .DESCRIPTION
        The WindowsFeatureRuleConvert class is used to extract the windows feature from
        the check-content of the xccdf. Once a STIG rule is identified as a
        windows feature rule, it is passed to the WindowsFeatureRuleConvert class for
        parsing and validation.

#>
class WindowsFeatureRuleConvert : WindowsFeatureRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    WindowsFeatureRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a Windows Feature Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    WindowsFeatureRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetFeatureName()
        $this.SetFeatureInstallState()
        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the feature name from the check-content and sets the value
        .DESCRIPTION
            Gets the feature name from the xccdf content and sets the value. If
            the name that is returned is not valid, the parser status is set to fail.
    #>
    [void] SetFeatureName ()
    {
        $thisFeatureName = Get-WindowsFeatureName -CheckContent $this.RawString

        if (-not $this.SetStatus($thisFeatureName))
        {
            $this.set_Name($thisFeatureName)
        }
    }

    <#
        .SYNOPSIS
            Extracts the feature state from the check-content and sets the value
        .DESCRIPTION
            Gets the feature state from the xccdf content and sets the value. If
            the state that is returned is not valid, the parser status is set to fail.
    #>
    [void] SetFeatureInstallState ()
    {
        $thisInstallState = Get-FeatureInstallState -CheckContent $this.RawString

        if (-not $this.SetStatus($thisInstallState))
        {
            $this.set_Ensure($thisInstallState)
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match '(Get-Windows(Optional)?Feature|is not installed by default)' -and
            $CheckContent -NotMatch 'Required roles and features will vary based on the function of the individual system' -or
            $CheckContent -Match 'WebDAV Authoring Rules' -and
            $CheckContent -NotMatch 'HKEY_LOCAL_MACHINE'
        )
        {
            return $true
        }
        return $false
    }

    <#
        .SYNOPSIS
            Tests if a rule contains multiple checks
        .DESCRIPTION
            Search the rule text to determine if multiple {0} are defined
        .PARAMETER Name
            The feature name from the rule text from the check-content element
            in the xccdf
    #>
    <#{TODO}#> # HasMultipleRules is implemented inconsistently.
    [bool] HasMultipleRules ()
    {
        return (Test-MultipleWindowsFeatureRule -FeatureName $this.Name)
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. This method splits a windows feature into multiple rules.
            Each split rule id is appended with a dot and letter to keep reporting
            per the ID consistent. An example would be is V-1000 contained 2
            checks, then SplitMultipleRules would return 2 objects with rule ids
            V-1000.a and V-1000.b
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    [string[]] SplitMultipleRules ()
    {
        return (Split-WindowsFeatureRule -FeatureName $this.Name)
    }

    hidden [void] SetDscResource ()
    {
        # Assigns the appropriate Windows Feature DSC Resource
        if ($null -eq $this.DuplicateOf)
        {
            if ($global:stigTitle -match 'Windows 10')
            {
                $this.DscResource = 'WindowsOptionalFeature'
            }
            else
            {
                $this.DscResource = 'WindowsFeature'
            }
        }
        else
        {
            $this.DscResource = 'None'
        }
    }
    #endregion
}
