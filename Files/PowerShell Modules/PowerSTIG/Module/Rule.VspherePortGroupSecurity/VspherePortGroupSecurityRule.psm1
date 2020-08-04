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
    .PARAMETER ForgedTransmitsInherited
        The boolean answer to allowing forged transmits on port groups nherited from switch configuration
    .PARAMETER MacChangesInherited
                The boolean answer to allowing Mac Changes on port groups inherited from switch configuration
    .PARAMETER AllowPromiscuousInherited
                The boolean answer to allowing Promiscuous mode on port groups inherited from switch configuration

#>
class VspherePortGroupSecurityRule : Rule
{
    [string] $ForgedTransmitsInherited
    [string] $MacChangesInherited
    [string] $AllowPromiscuousInherited

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    VspherePortGroupSecurityRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    VspherePortGroupSecurityRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    VspherePortGroupSecurityRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
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
