# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereKernelActiveDumpPartitionRule.psm1

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
        The VsphereRule class is used to extract the Vsphere settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere rule, it is passed to the VsphereRule class for parsing
        and validation.
#>
class VsphereKernelActiveDumpPartitionRuleConvert : VsphereKernelActiveDumpPartitionRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory.
    #>
    VsphereKernelActiveDumpPartitionRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Kernel Active Dump Partition Rule.
        .PARAMETER XccdfRule
            The STIG rule to convert.
    #>
    VsphereKernelActiveDumpPartitionRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $fixText = [VsphereKernelActiveDumpPartitionRule]::GetFixText($XccdfRule)
        $this.SetVsphereKernelActiveDumpPartition($fixText)
        $this.SetDscResource()
    }

    # Methods
    <#
    .SYNOPSIS
        Extracts the Kernel Active Dump Partition boolean from the fix text and sets the value.
    .DESCRIPTION
        Gets the boolean from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetVsphereKernelActiveDumpPartition ([string[]] $fixText)
    {
        $vsphereKernelActiveDumpPartition = Get-VsphereKernelActiveDumpPartition -FixText $fixText
        $this.set_Enabled($vsphereKernelActiveDumpPartition)
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostKernelActiveDumpPartition'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'coredump.partition')
        {
            return $true
        }

        return $false
    }
}
