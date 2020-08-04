# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The ServiceRule class is used to maange the Account Policy Settings.
    .PARAMETER ServiceName
        The service name
    .PARAMETER ServiceState
        The state the service should be in
    .PARAMETER StartupType
        The startup type of the service
    .PARAMETER Ensure
        A present or absent flag
#>
class ServiceRule : Rule
{
    [string] $ServiceName
    [string] $ServiceState
    [string] $StartupType <#(ExceptionValue)#>
    [ensure] $Ensure

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    ServiceRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    ServiceRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    ServiceRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
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
