# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The UserRightRule class is used to maange the Account Policy Settings.
    .PARAMETER DisplayName
        The user right display name
    .PARAMETER Constant
        The user right constant
    .PARAMETER Identity
        The identitys that should have the user right
    .PARAMETER Force
        A flag that replaces the identities vs append
#>
class UserRightRule : Rule
{
    [ValidateNotNullOrEmpty()] [string] $DisplayName
    [ValidateNotNullOrEmpty()] [string] $Constant
    [ValidateNotNullOrEmpty()] [string] $Identity <#(ExceptionValue)#>
    [bool] $Force = $false

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    UserRightRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    UserRightRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    UserRightRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [PSObject] GetExceptionHelp()
    {
        return @{
            Value = "Administrators"
            Notes = $null
        }
    }
}
