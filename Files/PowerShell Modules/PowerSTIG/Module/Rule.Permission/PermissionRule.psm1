# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Account Policy Rule object
    .DESCRIPTION
        The PermissionRule class is used to maange the Account Policy Settings.
    .PARAMETER Path
        The path to the object the permissions apply to
    .PARAMETER AccessControlEntry
        The ACE to be set on the path property
    .PARAMETER Force
        A flag that will overwrite the current ACE in the ACL instead of merge
#>
class PermissionRule : Rule
{
    [string] $Path
    [object[]] $AccessControlEntry <#(ExceptionValue)#>
    [bool] $Force

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    PermissionRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    PermissionRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    PermissionRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
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
