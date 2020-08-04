# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Vsphere Rule object
    .DESCRIPTION
        The Vsphere Kernel ActiveDump Partition class is used to maange the Vmware Vsphere Settings.
    .PARAMETER Enabled
        The boolean $true or $false to enable or disable this feature.
#>
class VsphereKernelActiveDumpPartitionRule : Rule
{
    [string] $Enabled

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    VsphereKernelActiveDumpPartitionRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    VsphereKernelActiveDumpPartitionRule ([xml.xmlelement] $Rule) : base ($Rule)
    {
    }

    <#
        .SYNOPSIS
            The Convert child class constructor
        .PARAMETER Rule
            The STIG rule to convert
        .PARAMETER Convert
            A simple bool flag to create a unique constructor signature
    #>
    VsphereKernelActiveDumpPartitionRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [hashtable] GetExceptionHelp()
    {
        return @{
            Value = "15"
            Notes = $null
        }
    }
}
