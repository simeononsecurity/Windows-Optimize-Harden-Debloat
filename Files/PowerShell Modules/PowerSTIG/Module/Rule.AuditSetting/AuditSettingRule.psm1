# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An AuditSetting Rule object
    .DESCRIPTION
        The AuditSettingRule class is used to maange the AuditSetting settings.
    .PARAMETER Query
        The AuditSetting class query
    .PARAMETER Property
        The class property
    .PARAMETER DesiredValue
        The desired value the property should be set to
    .PARAMETER Operator
        The PowerShell equivalent operator

#>
class AuditSettingRule : Rule
{
    [string] $Query
    [string] $Property
    [string] $DesiredValue
    [string] $Operator <#(ExceptionValue)#>

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    AuditSettingRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    AuditSettingRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    AuditSettingRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [PSObject] GetExceptionHelp()
    {
        return @{
            Value = "15"
            Notes = $null
        }
    }
}
