# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\ServiceRule.psm1

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
        Convert the contents of an xccdf check-content element into a ServiceRule object
    .DESCRIPTION
        The ServiceRule class is used to extract the Service settings from the
        check-content of the xccdf. Once a STIG rule is identified a service rule,
        it is passed to the ServiceRule class for parsing and validation.
#>
class ServiceRuleConvert : ServiceRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    ServiceRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a Service Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    ServiceRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetServiceName()
        $this.SetServiceState()
        $this.SetStartupType()
        $this.SetDuplicateRule()
        $this.SetDscResource()
    }

    #region Methods

    <#
        .SYNOPSIS
            Extracts the service name from the check-content and sets the value
        .DESCRIPTION
            Gets the service name from the xccdf content and sets the value. If
            the name that is returned is not valid, the parser status is set to
            fail.
    #>
    [void] SetServiceName ()
    {
        $thisServiceName = Get-ServiceName -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisServiceName))
        {
            $this.set_ServiceName($thisServiceName)
            $this.set_Ensure([ensure]::Present)
        }
    }

    <#
        .SYNOPSIS
            Extracts the service state from the check-content and sets the value
        .DESCRIPTION
            Gets the service state from the xccdf content and sets the value. If
            the state that is returned is not valid, the parser status is set to
            fail.
    #>
    [void] SetServiceState ()
    {
        $thisServiceState = Get-ServiceState -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisServiceState))
        {
            $this.set_ServiceState($thisServiceState)
        }
    }

    <#
        .SYNOPSIS
            Extracts the service startup type from the check-content and sets
            the value
        .DESCRIPTION
            Gets the service startup type from the xccdf content and sets the
            value. If the startup type that is returned is not valid, the parser
            status is set to  fail.
    #>
    [void] SetStartupType ()
    {
        $thisServiceStartupType = Get-ServiceStartupType -CheckContent $this.SplitCheckContent

        if (-not $this.SetStatus($thisServiceStartupType))
        {
            $this.set_StartupType($thisServiceStartupType)
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if
        (
            $CheckContent -Match 'services\.msc' -and
            $CheckContent -NotMatch 'Required Services' -and
            $CheckContent -NotMatch 'presence of applications' -and
            $CheckContent -NotMatch 'is not installed by default' -and
            $CheckContent -NotMatch 'Sql Server'
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
            Search the rule text to determine if multiple services are defined
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    <#{TODO}#> # HasMultipleRules is implemented inconsistently.
    [bool] HasMultipleRules ()
    {
        return (Test-MultipleServiceRule -ServiceName $this.Servicename)
    }

    <#
        .SYNOPSIS
            Splits a rule into multiple checks
        .DESCRIPTION
            Once a rule has been found to have multiple checks, the rule needs
            to be split. This method splits a services into multiple rules. Each
            split rule id is appended with a dot and letter to keep reporting
            per the ID consistent. An example would be is V-1000 contained 2
            checks, then SplitMultipleRules would return 2 objects with rule ids
            V-1000.a and V-1000.b.
        .PARAMETER CheckContent
            The rule text from the check-content element in the xccdf
    #>
    [string[]] SplitMultipleRules ()
    {
        return (Split-MultipleServiceRule -ServiceName $this.Servicename)
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'Service'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }
    #endregion
}
