# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The WindowsFeatureRule class is used to maange the Account Policy Settings.
    .PARAMETER Name
        The windows feature name
    .PARAMETER Ensure
        The state the windows feature should be in
#>
class WindowsFeatureRule : Rule
{
    [string] $Name
    [string] $Ensure <#(ExceptionValue)#>

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    WindowsFeatureRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    WindowsFeatureRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    WindowsFeatureRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [PSObject] GetExceptionHelp()
    {
        if ($this.Ensure -eq 'Present')
        {
            $thisInstallState = 'Absent'
        }
        else
        {
            $thisInstallState = 'Present'
        }

        return @{
            Value = $thisInstallState
            Notes = "'Present' and 'Absent' are the only valid values."
        }
    }
}
