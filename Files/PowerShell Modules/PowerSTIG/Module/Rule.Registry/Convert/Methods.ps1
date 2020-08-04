# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

#region Method Functions
<#
    .SYNOPSIS
        Determines what function to use to extract the registry key from a string. This is used to
        account for all of the different variations on registry setting in different STIGs.

    .PARAMETER stigString
        This is an array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryKey
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $result = @()
    if (Test-SingleLineRegistryRule -CheckContent $checkContent)
    {
        $result = Get-SingleLineRegistryPath -CheckContent $checkContent

        if ($result -match 'HKEY_LOCAL_MACHINE\\Software\\McAfee\\\s\(32-bit\)|HKLM\\Software\\Wow6432Node\\McAfee\\\s\(64-bit\)')
        {
            $result = Get-McAfeeRegistryPath -CheckContent $CheckContent
        }

        if ($result -match "!")
        {
            $result = $result.Substring(0, $result.IndexOf('!'))
        }
    }
    else
    {
        # Get the registry hive from the content string
        $registryHive = Get-RegistryHiveFromWindowsStig -CheckContent $checkContent

        # Get the registry path from the content string
        $registryPath = Get-RegistryPathFromWindowsStig -CheckContent $checkContent

        foreach ($path in $registryPath)
        {
            $result += ($registryHive + $path)
        }
    }

    $result
}

<#
    .SYNOPSIS
        Extract the registry key root from a string.

    .PARAMETER CheckContent
        An array of the raw string data taken from the STIG setting.
#>
function Get-RegistryHiveFromWindowsStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # Get the second index of the list, which should be the hive and remove spaces.
    $hive = ( ( $checkContent | Select-String -Pattern $regularExpression.RegistryHive ) -split ":" )[1]

    if ( -not [string]::IsNullOrEmpty( $hive ) )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $true"

        $hive = $hive.trim()

        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Trimmed : $hive"
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $false"
        throw "Registry hive was not found in check content."
    }

    $hive
}

<#
    .SYNOPSIS
        Extract the registry path from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting. the raw sting data taken from the STIG setting.
#>
function Get-RegistryPathFromWindowsStig
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $result = @()
    $paths = ( $checkContent | Select-String -Pattern $regularExpression.registryPath )

    if ( [string]::IsNullOrEmpty($paths) )
    {
        throw "Registry path was not found in check content."
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $false"
    }
    else
    {
        foreach ( $path in $paths.Line )
        {
            if ( $path -match ':' )
            {
                # Get the second index of the list, which should be the path and remove spaces.
                $path = (($path -split ":")[1])
            }

            $path = $path.trim().TrimEnd("\")

            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Trimmed : $path"

            # There are several cases where the leading backslash is missing, so add it back.
            if ( $path -notmatch "^\\" )
            {
                $path = "\$path"
                Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Fixed Leading Backslash : $path"
            }

            $result += $path
        }
    }

    $result
}

<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # The Office format is different to check which way to send the strings.
    if ( Test-SingleLineStigFormat -CheckContent $checkContent )
    {
        [string] $type = Get-RegistryValueTypeFromSingleLineStig -CheckContent $checkContent
    }
    else
    {
        # Get the second index of the list, which should be the data type and remove spaces.
        [string] $type = Get-RegistryValueTypeFromWindowsStig -CheckContent $checkContent
    }

    [string] $dscRegistryValueType = $dscRegistryValueType.$type
    # Verify the registry type against the dscRegistryValueType data section.
    if ( -not [string]::IsNullOrEmpty( $dscRegistryValueType ) )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]  Convert Type : $dscRegistryValueType "
        # Set the dsc format of the registry type
        [string] $return = $dscRegistryValueType
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] DSC Format Not Found For Type : $type"
        return
    }

    $return
}

<#
    .SYNOPSIS
        Tests that the ValueType is able to be used in a STIG

    .PARAMETER TestValueType
        The string to test against known good ValueTypes
#>
function Test-RegistryValueType
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $TestValueType
    )

    foreach ($valueType in $dscRegistryValueType.Keys)
    {
        if ($TestValueType -match $valueType)
        {
            $return = $valueType
            break
        }
    }

    if ($null -eq $return)
    {
        $return = $TestValueType
    }

    return $return
}

<#
    .SYNOPSIS
        Extract the registry value type from a Windows STIG string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueTypeFromWindowsStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $type = ( $checkContent | Select-String -Pattern $regularExpression.registryEntryType ).Matches.Value

    if ( -not [string]::IsNullOrEmpty( $type ) )
    {
        # Get the second index of the list, which should be the data type and remove spaces.
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]    Found : $type"

        $type = ( ($type -split ":")[1] ).trim()

        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]  Trimmed : $type"
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $false"
        # If we get here, there is nothing to verify so return.
        return
    }

    $type
}

<#
    .SYNOPSIS
        Extract the registry value type from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueName
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # The Office format is different to check which way to send the strings.
    if ( Test-SingleLineStigFormat -CheckContent $checkContent )
    {
        Get-RegistryValueNameFromSingleLineStig -CheckContent $checkContent
    }
    else
    {
        Get-RegistryValueNameFromWindowsStig -CheckContent $checkContent
    }
}

<#
    .SYNOPSIS
        Extract the registry value name from a string.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueNameFromWindowsStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # Get the second index of the list, which should be the data type and remove spaces
    [string] $name = ( ( $checkContent |
                Select-String -Pattern $regularExpression.registryValueName ) -split ":" )[1]

    if ( -not [string]::IsNullOrEmpty( $name ) )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $true"

        $return = $name.trim()

        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Trimmed : $name"
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $false"
        return
    }

    return $return
}

<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueData
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    # The Office format is different to check which way to send the strings.
    switch ( $true )
    {
        { Test-SingleLineStigFormat -CheckContent $checkContent }
        {
            return Get-RegistryValueDataFromSingleStig -CheckContent $checkContent
        }
        default
        {
            return Get-RegistryValueDataFromWindowsStig -CheckContent $checkContent
        }
    }
}

<#
    .SYNOPSIS
        Looks for multiple patterns in the value string to extract out the value to return or determine
        if additional processing is required. For example if an allowable range detected, additional
        functions need to be called to convert the text into powershell operators.

    .PARAMETER CheckContent
        An array of the raw sting data taken from the STIG setting.
#>
function Get-RegistryValueDataFromWindowsStig
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    $valueString = ( $checkContent | Select-String -Pattern $regularExpression.registryValueData )
    <#
        Get the second index of the list, which should be the data and remove spaces
    #>
    [string] $initialData = ( $valueString -replace $regularExpression.registryValueData )

    if ( -not [string]::IsNullOrEmpty( $initialData ) )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $true"

        $return = $initialData.trim()

        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Trimmed : $return"
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)]   Found : $false"
        # If the no data was found return, becasue there is nothing to further process.
        return
    }

    $return
}

<#
    .SYNOPSIS
        Checks if a string contains the literal word Blank

    .PARAMETER ValueDataString
        String from the STIG to check

    .NOTES
        This is an edge case function.
#>
function Test-RegistryValueDataIsBlank
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueDataString
    )
    <#
        There is an edge case that returns the string (Blank) with the expected return to be an
        empty string. No further processing is necessary, so simply return the empty string.
    #>
    if ( $ValueDataString -Match $regularExpression.blankString )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $true"
        return $true
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Checks if a string contains the literal word Enabled or Disabled

    .PARAMETER ValueDataString
        String from the STIG to check

    .NOTES
        This is an edge case function.
#>
function Test-RegistryValueDataIsEnabledOrDisabled
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueDataString
    )
    <#
        Here is an edge case that returns the string (Blank) with the expected return to be an
        empty string. No further processing is necessary, so simply return the empty string.
    #>
    if ( $ValueDataString -Match $regularExpression.enabledOrDisabled )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $true"
        return $true
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Checks if a string contains the literal word Enabled or Disabled

    .PARAMETER ValueDataString
        String from the STIG to check

    .NOTES
        This is an edge case function.
#>
function Get-ValidEnabledOrDisabled
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ValueType,

        [Parameter(Mandatory = $true)]
        [string]
        $ValueData
    )
    <#
        There is an edge case where Enabled|Disabled is used in place of the Dword int
        Get the integer value for the string, otherwise leave the data value as is.
    #>
    if ( $ValueType -eq 'Dword' -and -not (Test-IsValidDword -ValueData $ValueData) )
    {
        ConvertTo-ValidDword -ValueData $ValueData
    }
    else
    {
        $ValueData
    }
}

<#
    .SYNOPSIS
        Checks if a string contains a hexadecimal number

    .PARAMETER ValueDataString
        String from the STIG to check

    .NOTES
        This is an edge case function.
#>
function Test-RegistryValueDataIsHexCode
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueDataString
    )
    <#
        There is an edge case that returns the string (Blank) with the expected return to be an
        empty string. No further processing is necessary, so simply return the empty string.
    #>
    if ( $ValueDataString -Match $regularExpression.hexCode )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $true"
        return $true
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Returns the integer of a hexadecimal number

    .PARAMETER ValueDataString
        String from the STIG to Convert

    .NOTES
        Extract the hex code if it exists, convert to int32 and set the output value. This ignores the
        int that usually accompanies the hex value in parentheses.
#>
function Get-IntegerFromHex
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ValueDataString
    )

    $ValueDataString -Match $regularExpression.hexCode | Out-Null

    try
    {
        [convert]::ToInt32($matches[0], 16)
    }
    catch
    {
        throw "Could not convert $($matches[0]) into an integer"
    }
}

<#
    .SYNOPSIS
        Checks if a string contains a hexadecimal number

    .PARAMETER ValueDataString
        String from the STIG to check

    .NOTES
        This will match any lines that start with an integer (of any length) as the value to be set
#>
function Test-RegistryValueDataIsInteger
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueDataString
    )

    if ( $ValueDataString -Match $regularExpression.leadingIntegerUnbound -and
            $ValueDataString -NotMatch $regularExpression.hardenUncPathValues )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $true"
        return $true
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Returns the number from a string

    .PARAMETER ValueDataString
        String from the STIG to Convert
#>
function Get-NumberFromString
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ValueDataString
    )

    $string = Select-String -InputObject $ValueDataString `
                            -Pattern $regularExpression.leadingIntegerUnbound
    if ($null -eq $string)
    {
        throw
    }
    else
    {
        return $string.Matches[0].Value
    }
}

<#
    .SYNOPSIS
        Determines if a STIG check has a range of valid options.

    .DESCRIPTION
        There are serveral instances where a STIG check allows for a range of compliant values. This
        function reads the value string of a registry entry and if it discovers a sentence structure
        that provides for more than one value and $true flag is returned. If a fixed value is found
        a $false bool is returned.

    .PARAMETER ValueDataString
        The string to be tested.

    .EXAMPLE
        This example turns $true
        Test-RegistryValueDataContainsRange -ValueDataString "Value: 0x00008000 (32768) (or greater)"

    .EXAMPLE
        This example turns $false
        Test-RegistryValueDataContainsRange -ValueDataString "Value: 1"

    .NOTES
        General notes
#>
function Test-RegistryValueDataContainsRange
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueDataString
    )

    # Is in a word boundary since it is a common pattern
    if ( $ValueDataString -match $regularExpression.registryValueRange -and
         $ValueDataString -notmatch 'Disabled or' )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $true"
        return $true
    }
    else
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] $false"
        return $false
    }
}

<#
    .SYNOPSIS
        Formats a string value into a multiline string by spliting it on a space or comma space format.

    .PARAMETER ValueDataString
        The registry value data string to split.

    .NOTES
        General notes
#>
function Format-MultiStringRegistryData
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ValueDataString
    )

    $regEx = "\s|,\s"

    Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Formatting Multi String Data"

    return ( $ValueDataString -split $regEx ) -join ";"
}

<#
    .SYNOPSIS
        Formats a string value into a multiline string by spliting it on a space or comma space foramt.

    .PARAMETER CheckStrings
        The registry value data string to split.

    .NOTES
        General notes
#>
function Get-MultiValueRegistryStringData
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckStrings
    )

    $multiStringEntries = [String]$CheckStrings |
        Select-String -Pattern $regularExpression.MultiStringNamedPipe -AllMatches

    $multiStringList = @()
    foreach ( $entry in $multiStringEntries.Matches )
    {
        $multiStringList += $entry.Value.ToString().Trim()
    }

    return $multiStringList -join ";"
}

<#
    .SYNOPSIS
        Verifies that the discovered dword is an integer.

    .DESCRIPTION
        Dword registry data can only contain integers. This function provides a quick validation of
        the data that was extracted from the stig string to further increase the confidence of the
        conversion process.

    .PARAMETER ValueData
        The string to be tested.

    .EXAMPLE
        This example turns $true
        Test-IsValidDword -ValueData "3"

    .EXAMPLE
        This example turns $false
        Test-IsValidDword -ValueData "Three"

    .NOTES
        General notes
#>
function Test-IsValidDword
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string]
        $ValueData
    )
    <#
        Since this is a simple validation function we only need to know if it is a valide integer.
        If .Net can't figure it out, neither can we.
    #>
    try
    {
        [void] [System.Convert]::ToInt32( $ValueData )
    }
    catch [System.Exception]
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Valid Dword : $false"
        return $false
    }

    Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Valid Dword : $true"
    return $true
}

<#
    .SYNOPSIS
        Convert a string field into the correct dword value.

    .DESCRIPTION
        Several STIG settings provide the dword value in text or enumation format
        This function converts the english text value back into a a bit flag the dword accepts.

    .PARAMETER ValueData
        The text string to convert.

    .EXAMPLE
        In this example the string value "Enabled" is converted into the integer 1 and returned

        ConvertTo-ValidDword -ValueData "Enabled"

    .NOTES
        General notes
#>
function ConvertTo-ValidDword
{
    [CmdletBinding()]
    [OutputType([int])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $ValueData
    )

    $conversionTable = @{
        Enabled  = 1
        Disabled = 0
    }

    <#
        There is an edge case the puts the data in the '1 (Enabled)' format
        pull out the string and convert it to the integer.
    #>
    $ValueData -Match $regularExpression.enabledOrDisabled | Out-Null

    $ValueData = $matches[0]
    if ( $null -ne $conversionTable.$ValueData )
    {
        Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Valid Dword : $conversionTable.$ValueData"
        $conversionTable.$ValueData
    }
    else
    {
        throw "'$ValueData' is not a valid dword enumeration."
    }
}

<#
    .SYNOPSIS
        There are several rules that publish multiple registry settings in a single rule.
        This function will check for multiple entries. Some of the entries have a single
        Hive or path and multiple values.

    .PARAMETER CheckContent
        The standard check content string to look for duplicate entries.

    .NOTES
        General notes
#>
function Test-MultipleRegistryEntries
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    if (Test-SingleLineStigFormat -CheckContent $checkContent)
    {
        $matches = $checkContent | Select-String -Pattern "(HKLM|HKCU)\\(?!Software\\McAfee)" -AllMatches

        if ($matches.Matches.Count -gt 1 -and $matches -match 'outlook\\security')
        {
            return $false
        }

        if ( $matches.Matches.Count -gt 1 )
        {
            return $true
        }

        return $false
    }
    else
    {
        [int] $hiveCount = ($checkContent |
                Select-String -Pattern $regularExpression.registryHive ).Count

        [int] $pathCount = ($checkContent |
                Select-String -Pattern $regularExpression.registryPath ).Count

        [int] $valueCount = ($checkContent |
                Select-String -Pattern $regularExpression.registryValueData ).Count

        [int] $valueNameCount = ($checkContent |
                Select-String -Pattern $regularExpression.registryValueName ).Count

        if ( ( $hiveCount + $pathCount + $valueCount + $valueNameCount ) -gt 4 )
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Multiple Entries : $true"
            return $true
        }
        else
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Multiple Entries : $false"
            return $false
        }
    }
}

<#
    .SYNOPSIS
        Splits multiple registry entries from a single check into individual check strings.

    .PARAMETER CheckContent
        The standard check content string to split.

    .NOTES
        General notes
#>
function Split-MultipleRegistryEntries
{
    [CmdletBinding()]
    [OutputType([System.Collections.ArrayList])]
    param
    (
        [Parameter(Mandatory = $true)]
        [psobject]
        $CheckContent
    )

    [int] $registryEntryCounter = 0
    [System.Collections.ArrayList] $registryEntries = @()

    if ( Test-SingleLineStigFormat -CheckContent $checkContent )
    {
        $paths = $checkContent | Select-String "(HKLM|HKCU)\\" -AllMatches

        if ( $paths.Matches.Count -gt 1 )
        {
            if ( $paths -match 'Procedure:' )
            {
                $paths = $($checkContent -join " ") -Split "AND(\s*)Procedure:"
            }

            if ( $checkContent -match 'Navigate to:' )
            {
                $keys = @()
                $paths = @()
                foreach ($line in $checkContent)
                {
                    if ( $line -match '^(HKLM|HKCU)' )
                    {
                        $keys += $line
                    }

                    if ( $line -match 'REG_DWORD value' )
                    {
                        foreach ($key in $keys)
                        {
                            $add = $key, $line -join " "
                            $paths += $add
                        }
                        $keys = @()
                    }
                }
            }
        }

        if ($paths.Count -lt 2)
        {
            if ( $paths -match " and the " )
            {
                $paths = $paths -split " and the "
            }
            else
            {
                $paths = $paths -split " and "
            }
        }
        foreach ($path in $paths)
        {
            if (![string]::IsNullOrWhiteSpace($path))
            {
                [void] $registryEntries.Add( $path )
                $registryEntryCounter ++
            }
        }
    }
    else
    {
        $hives  = $checkContent | Select-String -Pattern $regularExpression.registryHive
        $paths  = $checkContent | Select-String -Pattern $regularExpression.registryPath
        $types  = $checkContent | Select-String -Pattern $regularExpression.registryEntryType
        $names  = $checkContent | Select-String -Pattern $regularExpression.registryValueName
        $values = $checkContent | Select-String -Pattern $regularExpression.registryValueData

        # If a check contains a multiple registry hives, then reference each one that is discovered.
        if ( $hives.Count -gt 1 )
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Hives : $($hives.Count)"

            foreach ( $registryRule in $hives )
            {
                $newSplitRegistryEntry = @(
                    $hives[$registryEntryCounter],
                    $paths[$registryEntryCounter],
                    $types[$registryEntryCounter],
                    $names[$registryEntryCounter],
                    $values[$registryEntryCounter]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
        <#
            If a check contains only the registry hive, but have multiple/unique paths,type,names,and values, then reference the single
            hive for each path that is discovered.
        #>
        elseif ($paths.count -gt 1 -and $types.count -eq 1 -and $names.count -eq 1 -and $values.count -eq 1)
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Paths : $($paths.count)"

            foreach ($registryRule in $paths)
            {
                $newSplitRegistryEntry = @(
                    $hives[0],
                    $paths[$registryEntryCounter],
                    $types[0],
                    $names[0],
                    $values[0]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
        <#
            If a check contains a single registry hive, path, type, and value, but multiple value names, then reference
            the single hive hive, path, type, and value for each value name that is discovered.
        #>
        elseif ($names.count -gt 1 -and $types.count -eq 1 -and $values.count -eq 1)
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Values : $($names.count)"

            foreach ($registryRule in $names)
            {
                $newSplitRegistryEntry = @(
                    $hives[0],
                    $paths[0],
                    $types[0],
                    $names[$registryEntryCounter],
                    $values[0]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
        <#
            If a check contains a single registry hive and path, but multiple values, then reference
            the single hive and path for each value name that is discovered.
        #>
        elseif ($names.count -gt 1 -and $types.count -gt 1)
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] Values : $($names.count)"

            foreach ($registryRule in $names)
            {
                $newSplitRegistryEntry = @(
                    $hives[0],
                    $paths[0],
                    $types[$registryEntryCounter],
                    $names[$registryEntryCounter],
                    $values[$registryEntryCounter]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
        elseif ($hives.count -eq 1 -and $paths.count -gt 1 -and $types.count -eq 1 -and $names.count -eq 1 -and $values.count -eq 1)
        {
            foreach ( $registryRule in $names )
            {
                $newSplitRegistryEntry = @(
                    $hives[0],
                    $paths[$registryEntryCounter],
                    $types[0],
                    $names[0],
                    $values[0]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
        elseif ($hives.count -eq 1 -and $paths.count -eq 1 -and $types.count -eq 1 -and $names.count -gt 1 -and $values.count -gt 1)
        {
            foreach ($registryRule in $values)
            {
                $newSplitRegistryEntry = @(
                    $hives[0],
                    $paths[0],
                    $types[0],
                    $names[$registryEntryCounter],
                    $values[$registryEntryCounter]) -join "`r`n"

                [void] $registryEntries.Add( $newSplitRegistryEntry )
                $registryEntryCounter ++
            }
        }
    }

    return $registryEntries
}

<#
    .SYNOPSIS
        Creates a registry pattern table and increments the pattern count from the single line functions

    .PARAMETER Pattern
        A registry rule pattern that has been applied

    .PARAMETER Rule
        Specifies a rule to include in output

    .NOTES
        Rules are not currently being captured in the results
        It is an optional parameter that can be included in the future
#>
function Set-RegistryPatternLog
{
    [CmdletBinding()]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Pattern,

        [Parameter()]
        [string]
        $Rule
    )

    <#
       Load table with patterns from Core data file.
       Build the in-memory table of patterns
    #>
    if (-not $global:patternTable)
    {
        $nonestedItems = $global:SingleLineRegistryPath.GetEnumerator() |
        Where-Object { $_.Value['Select'] -ne $null }

        $nestedItems = $global:SingleLineRegistryPath.GetEnumerator() |
        Where-Object { $_.Value['Select'] -eq $null } | Select-Object {$_.Value } -ExpandProperty Value

        $regPathTable = $nonestedItems.GetEnumerator() |
        ForEach-Object { New-Object -TypeName PSObject -Property @{Pattern=$_.Value['Select']; Count=0; Type='RegistryPath'}}

        $regPathTable += $nestedItems.GetEnumerator() |
        Where-Object { $_.Value['Select'] -ne $null } |
        ForEach-Object { New-Object -TypeName PSObject -Property @{Pattern=$_.Value['Select']; Count=0; Type='RegistryPath'}}

        $regValueTypeTable = $global:SingleLineRegistryValueType.GetEnumerator() |
        Where-Object { $_.Value['Select'] -ne $null } |
        ForEach-Object { New-Object -TypeName PSObject -Property @{Pattern=$_.Value['Select']; Count=0; Type='ValueType'}}

        $regValueNameTable = $global:SingleLineRegistryValueName.GetEnumerator() |
        Where-Object { $_.Value['Select'] -ne $null } |
        ForEach-Object { New-Object -TypeName PSObject -Property @{Pattern=$_.Value['Select']; Count=0; Type='ValueName'}}

        $regValueDataTable = $global:SingleLineRegistryValueData.GetEnumerator() |
        Where-Object { $_.Value['Select'] -ne $null } |
        ForEach-Object { New-Object -TypeName PSObject -Property @{Pattern=$_.Value['Select']; Count=0; Type='ValueData'}}

        $valueTypeTable = $regValueTypeTable |
        Group-Object -Property "Pattern" |
        ForEach-Object{ $_.Group | Select-Object 'Pattern','Count', 'Type' -First 1}

        $valueNameTable = $regValueNameTable |
        Group-Object -Property "Pattern" |
        ForEach-Object{ $_.Group | Select-Object 'Pattern','Count', 'Type' -First 1}

        $valueDataTable = $regValueDataTable |
        Group-Object -Property "Pattern" |
        ForEach-Object{ $_.Group | Select-Object 'Pattern','Count', 'Type' -First 1}

        $global:patternTable = $regPathTable + $valueTypeTable + $valueNameTable + $valueDataTable
    }

    # Find pattern in table and increment count
    $searchResult = $global:patternTable | Where-Object { $_.Pattern -eq $Pattern}
    if ($searchResult)
    {
        $searchResult.Count ++
    }
}

<#
    .SYNOPSIS
        Lists registry rule patterns along with counts for the number of rules that use each pattern.

    .PARAMETER Path
        Specifies a path to a directory with (unprocessed) xccdf.xml files or a specific xccdf.xml file.
        Path should be StigData\Archive\{Directory Name} or StigData\Archive\{DirectoryName}\{*.xccdf.xml}

    .Notes
        Expression patterns are only for Registry Rules, this could change in the future
#>
function Get-RegistryPatternLog
{
    [CmdletBinding()]
    [OutputType([Object])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    try
    {
        # If $Path is a directory, get all files contained in it
        $isFolder = Test-Path $Path -pathType Container
        if ($isFolder)
        {
            $files = Get-ChildItem -Path $Path -Filter '*.xml'
            foreach ($file in $files)
            {
                if (Test-StigProcessed $file.FullName)
                {
                    ConvertFrom-StigXccdf -Path $file.FullName | Out-Null
                }
            }
        }

        # If $Path is a file, process it
        $isFile = Test-Path $Path -pathType Leaf
        if ($isFile)
        {
            if (Test-StigProcessed $Path)
            {
                ConvertFrom-StigXccdf -Path $Path | Out-Null
            }
        }
    }
    catch [System.IO.DirectoryNotFoundException],[System.IO.FileNotFoundException]
    {
        Write-Output "The path or file was not found: [$Path]"
    }
    catch [System.IO.IOException]
    {
        Write-Output "Error accessing path or file at: [$Path]"
    }

    # Return patterns table with counts
    return $global:patternTable
}

<#
    .SYNOPSIS
        Test if the check-content contains mitigations polices to enable.

    .PARAMETER Path
        Specifies the check-content element in the xccdf

    .Notes
        Currently all rules in the STIG state the policies referenced need to be enabled.
        However that could change in the future or in other STIGs so we need to check for both conditions (Enabled|Disabled)
#>
function Test-StigProcessed
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string[]]
        $Path
    )
    # Setup, check $Path for Processed
    [xml]$XmlDocument = Get-Content -Path $Path
    $id = $XmlDocument.Benchmark | Select-Object id

    $version = $Path | Select-String -Pattern '(?<=_)V.*(?=_)' |
    ForEach-Object { $_.Matches[0] -replace "V", "" -replace "R","\." }

    $conversionPath = Get-Item "$($PSScriptRoot)..\..\..\StigData\Processed"
    #Write-Host $testPath
    $hasConversion = Get-ChildItem -Path $conversionPath -recurse | Where-Object { $_ | Select-String -Pattern $id.id } | Where-Object { $_ | Select-String -Pattern $version }
    #$hasConversion = Get-ChildItem -Path ..\..\..\StigData\Processed -recurse | Where-Object { $_ | Select-String -Pattern $id.id } | Where-Object { $_ | Select-String -Pattern $version }

    if ($hasConversion)
    {
        return $true
    }
    else
    {
        return $false
    }
}
#endregion
