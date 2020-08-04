# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereAcceptanceLevelRule.psm1

$exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
$supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude
foreach ($supportFile in $supportFileList)
{
    Write-Verbose -Message "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}

<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a Vsphere object.
    .DESCRIPTION
        The VsphereRule Acceptance Level class is used to extract the Vsphere settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere Acceptance Level rule, it is passed to the VsphereRule Acceptance Level class for parsing
        and validation.
#>
class VsphereAcceptanceLevelRuleConvert : VsphereAcceptanceLevelRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    VsphereAcceptanceLevelRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    VsphereAcceptanceLevelRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $fixText = [VsphereAcceptanceLevelRule]::GetFixText($XccdfRule)
        $this.SetVsphereAcceptanceLevel($fixtext)
        $this.SetDscResource()
    }

    <#
    .SYNOPSIS
        Extracts the acceptance level from the fix text and sets the level
    .DESCRIPTION
        Gets the accceptance leve from the xccdf content and sets the level.
        If the level that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereAcceptanceLevel ([string[]] $Fixtext)
    {
        $vsphereAcceptanceLevel = Get-VsphereAcceptanceLevel -FixText $Fixtext
        $this.set_Level($vsphereAcceptanceLevel)
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostAcceptanceLevel'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'software.acceptance')
        {
            return $true
        }

        return $false
    }
}
