# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Public Function
<#
    .SYNOPSIS
        This public function calls ConvertFrom-StigXml and generates a basic report showing the
        results of the conversion, sorted by the type of stig setting that was evaluated.

    .PARAMETER Path
        The full path to the xccdf to convert.
#>
function Get-ConversionReport
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    # Read in the raw stig xml and get the list of types that are discovered
    [PSCustomObject] $global:stigSettings = ConvertFrom-StigXccdf -Path $path

    # Get the list of stig types or categories. This is used to sort and filter the results
    $ruleTypes = Get-RuleTypeList -StigSettings $global:stigSettings

    # Create an empty array to store the list in
    [System.Collections.ArrayList] $report = @()

    foreach ( $ruleType in $ruleTypes )
    {
        $reportItem = New-Object PSObject
        $reportItem | Add-Member -MemberType NoteProperty -Name Type -Value $ruleType

        <#
            Get all of the STIG settings discoverd for the current type
            The @ will force PS to return an array so the count method works properly
        #>
        $values = @( $global:stigSettings | Where-Object {$_.GetType().Name -eq $ruleType} )
        $reportItem | Add-Member -MemberType NoteProperty -Name Count -Value $values.Count

        <#
            Of the list of items that was just filtered above, count any that have an error
            The @ will force PS to return an array so the count method works properly
        #>
        $errorCount = @( $values | Where-Object 'status' -eq 'fail' ).Count
        $reportItem | Add-Member -MemberType NoteProperty -Name Errors -Value $errorCount

        <#
            Of the list of items that was filtered above, count all that pass the conversion
            The @ will force PS to return an array so the count method works properly
        #>
        $passcount = @($values | Where-Object 'conversionstatus' -eq 'pass').Count
        $reportItem | Add-Member -MemberType NoteProperty -Name ConversionPass -Value $passcount

        <#
            Of the list of items that was filtered above, count any that fail the conversion.
            The @ will force PS to return an array so the count method works properly
        #>
        $failcount = @( $values | Where-Object 'conversionstatus' -eq 'fail' ).Count
        $reportItem | Add-Member -MemberType NoteProperty -Name ConversionFail -Value $failcount

        [void] $report.Add($reportItem)
    }

    $report
}
#endregion
#region Private Functions
<#
    .SYNOPSIS
        Simply returns an alphabetical list of STIG types. This helps with additional
        sorting and searching.
#>
function Get-RuleTypeList
{
    param
    (
        [Parameter(Mandatory = $true)]
        [PSCustomObject]
        $StigSettings
    )

    $StigSettings |
        Foreach-Object {$PSItem.GetType().ToString()} |
            Select-Object -Unique |
                Sort-Object
}
#endregion
