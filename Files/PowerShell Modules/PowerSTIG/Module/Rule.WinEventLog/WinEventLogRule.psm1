# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The WinEventLogRule class is used to manage the Account Policy Settings.
    .PARAMETER LogName
        The name of the log
    .PARAMETER IsEnabled
        The enabled status of the log
#>
class WinEventLogRule : Rule
{
    [string] $LogName
    [bool] $IsEnabled <#(ExceptionValue)#>

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    WinEventLogRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    WinEventLogRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    WinEventLogRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [PSObject] GetExceptionHelp()
    {
        if ($this.IsEnabled -eq 'True')
        {
            $thisIsEnabled = 'False'
        }
        else
        {
            $thisIsEnabled = 'True'
        }
        return @{
            Value = $thisIsEnabled
            Notes = "'True' and 'False' are the only valid values"
        }
    }
}
