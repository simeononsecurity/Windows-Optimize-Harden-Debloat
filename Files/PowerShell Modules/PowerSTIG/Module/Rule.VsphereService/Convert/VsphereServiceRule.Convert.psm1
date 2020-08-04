# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\VsphereServiceRule.psm1

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
        Convert the contents of an xccdf check-content element into a VsphereServiceRule object
    .DESCRIPTION
        The VsphereServiceRule class is used to extract the Vsphere Service settings
        from the check-content of the xccdf. Once a STIG rule is identified a
        Vsphere Service rule, it is passed to the VsphereServiceRule class for parsing
        and validation.
#>
class VsphereServiceRuleConvert : VsphereServiceRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    VsphereServiceRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts an xccdf stig rule element into a Vsphere Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    VsphereServiceRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetKey()
        $this.SetPolicy()
        $this.SetDscResource()
    }

    # Methods
    <#
    .SYNOPSIS
        Extracts the Key (serviceName) from the check-content and sets the values
    .DESCRIPTION
        Gets the key from the xccdf content and sets the value.
        If the value that is returned is not valid, the parser status is
        set to fail.
    #>
    [void] SetKey ()
    {
        $key = Get-VsphereServiceKey -CheckContent $this.SplitCheckContent
        $this.set_Key($key)
    }

    <#
    .SYNOPSIS
        Extracts the service policy from the check-content and sets the values of policy and running state
    .DESCRIPTION
        Gets the policy from the check-content then sets both the policy and running state based on match.
    #>
    [void] SetPolicy ()
    {
        $policy = Get-VsphereServicePolicy -CheckContent $this.SplitCheckContent
        $this.set_Policy($policy[0])
        $this.set_Running($policy[1])
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'VMHostService'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -match 'Get-VMHostService')
        {
            return $true
        }

        return $false
    }
}
