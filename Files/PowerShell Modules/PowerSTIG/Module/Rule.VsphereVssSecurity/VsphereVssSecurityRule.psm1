# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Vsphere Rule object
    .DESCRIPTION
        The Vsphere class is used to maange the Vmware Vsphere Settings.
    .PARAMETER ForgedTransmits
        The boolean answer to allowing forged transmits on the switch configuration
    .PARAMETER MacChanges
        The boolean answer to allowing Mac Changes on the switch configuration
    .PARAMETER AllowPromiscuous
        The boolean answer to allowing Promiscuous mode on the switch configuration
#>
class VsphereVssSecurityRule : Rule
{
    [string] $ForgedTransmits
    [string] $MacChanges
    [string] $AllowPromiscuous

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    VsphereVssSecurityRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    VsphereVssSecurityRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    VsphereVssSecurityRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
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
