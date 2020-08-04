# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

using namespace system.xml

[System.Diagnostics.CodeAnalysis.SuppressMessage('PSUseDeclaredVarsMoreThanAssigments', '')]
[String] $resourcePath = (Resolve-Path -Path $PSScriptRoot\Resources).Path

<#
    .SYNOPSIS
        Applies a standard format of STIG data to resource titles.
    .PARAMETER Rule
        The Stig rule that is being created.
    .PARAMETER Instance
        The target instance name.
#>
function Get-ResourceTitle
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $Rule,

        [Parameter()]
        [string]
        $Instance
    )

    if ($Instance)
    {
        $Rule.title = "$($Rule.title):$Instance"
    }
    return "[$($Rule.Id)][$($Rule.severity)][$($Rule.title)]"
}

<#
    .SYNOPSIS
        Filters the STIG items to a specifc type.
    .PARAMETER RuleList
        The list of rules to filter.
    .PARAMETER Type
        The name of the rule type to return.
#>
function Select-Rule
{
    [CmdletBinding()]
    [OutputType([psobject])]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject[]]
        $RuleList,

        [Parameter(Mandatory = $true)]
        [string]
        $Type
    )

    process
    {
        return $RuleList.Where({
            $_.GetType().ToString() -eq $Type -and
            [string]::IsNullOrEmpty($_.DuplicateOf)
        })
    }
}

<#
    .SYNOPSIS
        Some STIG rules have redudant values that we only need to set once.
        This function will take all those values and only return the unique
        values as either an array or as string values joined by commas.
    .PARAMETER InputObject
        An array of strings.
    .PARAMETER AsString
        Switch parameter to indicate returning as a string joined by commas.
#>
function Get-UniqueStringArray
{
    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]]
        $InputObject,

        [Parameter()]
        [switch]
        $AsString
    )

    $return = @()

    foreach ($item in $InputObject.Where{ -not [String]::IsNullOrWhiteSpace($PSItem) })
    {
        $splitItems = $item -Split ','

        foreach ($string in $splitItems)
        {
            if (-not ($return -contains $string))
            {
                $return += $string
            }
        }
    }

    if ($AsString)
    {
        return ($return | Foreach-Object { "'$PSItem'" }) -join ','
    }
    else
    {
        return $return
    }
}

<#
    .SYNOPSIS
        Some STIG rules have redundant values that we only need to set once.
        This function will take those, validate there is only one unique value,
        then return it.
    .PARAMETER InputObject
        An array of strings.
#>
function Get-UniqueString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object[]]
        $InputObject
    )

    $return = $InputObject.Where{ -not [String]::IsNullOrWhiteSpace($PSItem) } |
        Select-Object -Unique

    if ($return.count -le 1)
    {
        return $return
    }
    else
    {
        throw 'Conflicting values found. Only one unique value can be used.'
    }
}

<#
    .SYNOPSIS
        The IIS STIG has multiple rules that specify logging custom field entries,
        but those need to be combined into one resource block and formatted as
        instances of MSFT_xLogCustomFieldInformation. This function will gather
        all those entries and return it in the format DSC requires.
    .PARAMETER LogCustomField
        An array of LogCustomField entries.
    .PARAMETER Resource
        Name of resource to use
#>
function Get-LogCustomField
{
    [CmdletBinding()]
    [OutputType([object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [object[]]
        $LogCustomField,

        [Parameter(Mandatory = $true)]
        [ValidateSet('xIisLogging', 'xWebSite')]
        [string]
        $Resource
    )

    $return = @()

    foreach ($entry in $LogCustomField)
    {
        $classInstance = [System.Text.StringBuilder]::new()

        switch ($Resource)
        {
            'xIisLogging'
            {
                $null = $classInstance.AppendLine("MSFT_xLogCustomField")
                break
            }
            'xWebSite'
            {
                $null = $classInstance.AppendLine("MSFT_xLogCustomFieldInformation")
                break
            }
        }
        $null = $classInstance.AppendLine("{")
        $null = $classInstance.AppendLine("LogFieldName = '$($entry.SourceName)'")
        $null = $classInstance.AppendLine("SourceName   = '$($entry.SourceName)'")
        $null = $classInstance.AppendLine("SourceType   = '$($entry.SourceType)'")
        $null = $classInstance.AppendLine("};")
        $return += $classInstance.ToString()
    }
    return $return
}
#endregion
#region FireFox

<#
    .SYNOPSIS
        Formats the value of a FireFox configuration preference. The FireFox.cfg
        file wants double quotes around words but not around bools or intergers.
    .PARAMETER Value
        Specifies the FireFox preference value to be formated.
#>
function Format-FireFoxPreference
{
    param
    (
        [Parameter()]
        [string]
        $Value
    )

    switch ($value)
    {
        {[Bool]::TryParse($value, [Ref]$null) }
        {
            $result = $value; break
        }
        { [Int]::TryParse($value, [Ref]$null) }
        {
            $result = $value; break
        }
        default
        {
            $result = '"' + $value + '"'
        }
    }
    return $result
}

<#
    .SYNOPSIS
        Formats a string to the standard needed by the SqlScriptQuery resource
        to pass a variable to the Sql query.
    .PARAMETER Variable
        A string formated to leverage the -f operator.
    .PARAMETER VariableValue
        Specifies the value of the variable used in the SQL query.
    .PARAMETER Database
        Specifies the name of the database.
#>
function Format-SqlScriptVariable
{
    [Cmdletbinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter()]
        [AllowEmptyString()]
        [string]
        $Variable,

        [Parameter()]
        [AllowEmptyString()]
        [string]
        $VariableValue,

        [Parameter()]
        [string]
        $Database
    )

    $counter = 0
    $results = @()
    if ([string]::IsNullOrWhiteSpace($Variable) -eq $false)
    {
        $variableNames = ($Variable | Select-String -Pattern '\w+\=\{\d\}' -AllMatches).Matches.Value

        foreach ($variableName in $variableNames)
        {
            $results += $variableName -replace '\{\d\}',"$(($VariableValue -split ',')[$counter])"
            $counter++
        }
    }

    if ([string]::IsNullOrWhiteSpace($Database) -eq $false)
    {
        $results += "Database=$Database"
    }

    return $results
}
#end region

Export-ModuleMember -Variable 'resourcePath' -Function @(
    'Get-ResourceTitle'
    'Select-Rule'
    'Get-UniqueString'
    'Get-UniqueStringArray'
    'Get-LogCustomField'
    'Format-FireFoxPreference'
    'Format-SqlScriptVariable'
)
