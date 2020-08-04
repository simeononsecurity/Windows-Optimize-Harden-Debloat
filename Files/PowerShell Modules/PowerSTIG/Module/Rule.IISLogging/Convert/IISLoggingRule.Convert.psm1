# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\IisLoggingRule.psm1


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
        Convert the contents of an xccdf check-content element into an IIS
        Logging object
    .DESCRIPTION
        The IisLoggingRuleConvert class is used to extract the IIS Log Settings from
        the check-content of the xccdf. Once a STIG rule is identified as an
        IIS Log rule, it is passed to the IisLoggingRuleConvert class for parsing
        and validation.
#>
class IisLoggingRuleConvert : IisLoggingRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    IisLoggingRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf stig rule element into a Iis Logging Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    IisLoggingRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetLogCustomFields()
        $this.SetLogFlags()
        $this.SetLogFormat()
        $this.SetLogPeriod()
        $this.SetLogTargetW3C()
        $this.SetStatus()
        $this.SetDscResource()
    }

    <#
        .SYNOPSIS
            Extracts the log custom field from the check-content and sets the value
        .DESCRIPTION
            Gets the log custom field from the xccdf content and sets the value.
            If the log custom field that is returned is not valid, the parser
            status is set to fail
    #>
    [void] SetLogCustomFields ()
    {
        $thisLogCustomField = Get-LogCustomFieldEntry -CheckContent $this.SplitCheckContent

        $this.set_LogCustomFieldEntry($thisLogCustomField)
    }

    <#
        .SYNOPSIS
            Extracts the log flag from the check-content and sets the value
        .DESCRIPTION
            Gets the log flag from the xccdf content and sets the value. If the
            log flag that is returned is not valid, the parser status is set
            to fail
    #>
    [void] SetLogFlags ()
    {
        $thisLogFlag = Get-LogFlag -CheckContent $this.SplitCheckContent

        if (-not [String]::IsNullOrEmpty($thisLogFlag))
        {
            $this.set_LogFlags($thisLogFlag)
        }
    }

    <#
        .SYNOPSIS
            Extracts the log format from the check-content and sets the value
        .DESCRIPTION
            Gets the log format from the xccdf content and sets the value. If the
            log format that is returned is not valid, the parser status is set
            to fail.
    #>
    [void] SetLogFormat ()
    {
        $thisLogFormat = Get-LogFormat -CheckContent $this.SplitCheckContent

        if (-not [String]::IsNullOrEmpty($thisLogFormat))
        {
            $this.set_LogFormat($thisLogFormat)
        }
    }

    <#
        .SYNOPSIS
            Extracts the log period from the check-content and sets the value
        .DESCRIPTION
            Gets the log period from the xccdf content and sets the value. If the
            log period that is returned is not valid, the parser status is set
            to fail.
    #>
    [void] SetLogPeriod ()
    {
        $thisLogPeriod = Get-LogPeriod -CheckContent $this.SplitCheckContent

        if (-not [String]::IsNullOrEmpty($thisLogPeriod))
        {
            $this.set_LogPeriod($thisLogPeriod)
        }
    }

    <#
        .SYNOPSIS
            Extracts the log target from the check-content and sets the value
        .DESCRIPTION
            Gets the log target from the xccdf content and sets the value. If the
            log target that is returned is not valid, the parser status is set
            to fail.
    #>
    [void] SetLogTargetW3C ()
    {
        $thisLogTargetW3C = Get-LogTargetW3C -CheckContent $this.SplitCheckContent

        if (-not [String]::IsNullOrEmpty($thisLogTargetW3C))
        {
            $this.set_LogTargetW3C($thisLogTargetW3C)
        }
    }

    <#
        .SYNOPSIS
            Validates the parsed data and sets the parser status
        .DESCRIPTION
            Compares the created rule object against and base stig object to
            make sure that all of the properties have be set to valid values.
    #>
    [void] SetStatus ()
    {
        $baseRule = $this.GetType().BaseType.BaseType::New()
        $referenceProperties = ($baseRule | Get-Member -MemberType Property).Name
        $differenceProperties = ($this | Get-Member -MemberType Property).Name
        $propertyList = (Compare-Object -ReferenceObject $referenceProperties -DifferenceObject $differenceProperties).InputObject

        $status = $false

        foreach ($property in $propertyList)
        {
            if ($null -ne $this.$property)
            {
                $status = $true
            }
        }

        if (-not $status)
        {
            $this.conversionstatus = [status]::fail
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            if ($global:stigTitle -match "Server")
            {
                $this.DscResource = 'xIISLogging'
            }
            else
            {
                $this.DscResource = 'XWebsite'
            }
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
            $CheckContent -Match 'Logging' -and
            $CheckContent -Match 'IIS 8\.5|IIS 10\.0' -and
            $CheckContent -NotMatch 'review source IP' -and
            $CheckContent -NotMatch 'verify only authorized groups' -and
            $CheckContent -NotMatch 'Confirm|Consult with the System Administrator' -and
            $CheckContent -Notmatch 'If an account associated with roles other than auditors'
        )
        {
            return $true
        }
        return $false
    }
    #endregion
}
