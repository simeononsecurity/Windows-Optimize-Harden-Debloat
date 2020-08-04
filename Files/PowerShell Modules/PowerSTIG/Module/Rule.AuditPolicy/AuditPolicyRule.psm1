# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        Audit Policy object to manage Audit Policy STIG Rules
    .DESCRIPTION
        The AuditPolicyRule class is used to manage the Audit Policy Settings
    .PARAMETER Subcategory
        The name of the subcategory to configure
    .PARAMETER AuditFlag
        The Success or failure flag
    .PARAMETER Ensure
        A present or absent flag
#>
class AuditPolicyRule : Rule
{
    [string] $Subcategory
    [string] $AuditFlag
    [ensure] $Ensure <#(ExceptionValue)#>

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    AuditPolicyRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    AuditPolicyRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    AuditPolicyRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
    {
    }

    <#
        .SYNOPSIS
            Creates class specifc help content
    #>
    [PSObject] GetExceptionHelp()
    {
        if ($this.Ensure -eq 'Absent')
        {
            $value = 'Present'
        }
        else
        {
            $value = 'Absent'
        }

        return @{
            Value = $value
            Notes = "'Present' and 'Absent' are the only valid values"
        }
    }
}
