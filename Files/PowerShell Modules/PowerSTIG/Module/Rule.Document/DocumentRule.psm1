# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\Common\Common.psm1
using module .\..\Rule\Rule.psm1
#header

<#
    .SYNOPSIS
        An Document Rule object
    .DESCRIPTION
        The DocumentRule class is used to maange the Document Settings.

#>
class DocumentRule : Rule
{
    <#
        .SYNOPSIS
            Constructor that fully populates the required properties
        .DESCRIPTION
            Constructor that fully populates the required properties
        .PARAMETER Id
            The STIG ID
        .PARAMETER Severity
            The STIG Severity
        .PARAMETER Title
            The STIG Title
        .PARAMETER RawString
            The chcek-content element of the STIG xccdf
    #>
    DocumentRule ([string] $Id, [severity] $Severity, [string] $Title, [string] $RawString)
    {
        $this.Id = $Id
        $this.severity = $Severity
        $this.title = $Title
        $this.rawString = $RawString
        $this.DscResource = 'None'
    }

    <#
        .SYNOPSIS
            Default constructor to support the AsRule cast method
    #>
    DocumentRule ()
    {
    }

    <#
        .SYNOPSIS
            Used to load PowerSTIG data from the processed data directory
        .PARAMETER Rule
            The STIG rule to load
    #>
    DocumentRule ([xml.xmlelement] $Rule) : base ($Rule)
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
    DocumentRule ([xml.xmlelement] $Rule, [switch] $Convert) : base ($Rule, $Convert)
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
