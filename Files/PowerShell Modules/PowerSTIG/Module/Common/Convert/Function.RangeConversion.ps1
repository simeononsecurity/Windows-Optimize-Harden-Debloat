#region Header
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#endregion
#region Main Functions
<#
    .SYNOPSIS
        This function is a selection function that looks at text containing conditional language and
        tries to identify the correct specialized function to set it to for conversion. The conversion
        functions called by this function do the English to PowerShell conversion.

    .PARAMETER String
        The STIG text contains conditional text to try and convert to a PowerShell expression.

    .NOTES
        General Notes
#>
function Get-OrganizationValueTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    switch ($string)
    {
        {Test-StringIsNegativeOr -String $PSItem}
        {
            ConvertTo-OrTestString -String $PSItem -Operator NotMatch
            continue
        }
        {Test-StringIsPositiveOr -String $PSItem}
        {
            ConvertTo-OrTestString -String $PSItem -Operator Match
            continue
        }
        {
            (Test-StringIsLessThan -String $PSItem)                 -or
            (Test-StringIsLessThanOrEqual -String $PSItem)          -or
            (Test-StringIsLessThanButNot -String $PSItem)           -or
            (Test-StringIsLessThanOrEqualButNot -String $PSItem)    -or
            (Test-StringIsLessThanOrEqualExcluding -String $PSItem) -or
            (Test-StringIsGreaterThan -String $PSItem)              -or
            (Test-StringIsGreaterThanOrEqual -String $PSItem)       -or
            (Test-StringIsGreaterThanButNot -String $PSItem)        -or
            (Test-StringIsGreaterThanOrEqualButNot -String $PSItem) -or
            (Test-StringIsBetweenTwoValues -String $PSItem)         -or
            (Test-StringHasOneValueOrDoesntExist -String $PSItem)
        }
        {
            ConvertTo-TestString -String $PSItem
            continue
        }
        {Test-StringIsMultipleValue -String $PSItem}
        {
            ConvertTo-MultipleValue -String $PSItem
            continue
        }
    }
}

function Get-TestStringTokenNumbers
{
    [CmdletBinding()]
    [OutputType([string[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    <#
        Some strings contain double quotes around numbers. This causes the
        PSParser to return them as a string vs a number, so the double quotes
        are stripped out before being parsed.
    #>
    $string = $String -replace '"',''

    $tokens = [System.Management.Automation.PSParser]::Tokenize($string, [ref]$null)
    $number = $tokens.Where({$PSItem.type -eq 'Number'}).Content
    <#
        There is an edge case where the hex and decimal values are provided inline, so pick
        the hex code out and convert it to an int.
    #>
    $match = $number | Select-String -Pattern "\b(0x[A-Fa-f0-9]{8}){1}\b"

    if ($match)
    {
        if ($number.count -gt 2)
        {
            $number[1, 2]
        }
        else
        {
            [convert]::ToInt32($match,16)
        }
    }
    else
    {
        $number
    }
}

<#
    .SYNOPSIS
        Uses the PowerShell parser to tokenize the English sentences into individual words that are
        regrouped and complied into PS representations that can be applied and measured automatically.
#>
function Get-TestStringTokenList
{
    [CmdletBinding(DefaultParameterSetName = 'CommandTokens')]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String,

        [Parameter(ParameterSetName = 'CommandTokens')]
        [switch]
        $CommandTokens,

        [Parameter(ParameterSetName = 'StringTokens')]
        [switch]
        $StringTokens
    )

    $tokens = [System.Management.Automation.PSParser]::Tokenize($string, [ref]$null)

    if ($PSCmdlet.ParameterSetName -eq 'StringTokens')
    {
        return $tokens.Where({ $PSItem.type -eq 'String' }).Content
    }

    $commands = $tokens.Where({
            $PSItem.type -eq 'CommandArgument' -or
            $PSItem.type -eq 'Command' }).Content
    return ( $commands -join " " )
}

function ConvertTo-TestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    $number    = Get-TestStringTokenNumbers -String $string
    $operators = Get-TestStringTokenList -String $string -CommandTokens

    switch ($operators)
    {
        'greater than'
        {
            return "'{0}' -gt '$number'"
        }
        'or greater'
        {
            return "'{0}' -ge '$number'"
        }
        'greater than but not'
        {
            return "'{0}' -gt '$($number[0])' -and '{0}' -lt '$($number[1])'"
        }
        'or greater but not'
        {
            return "'{0}' -ge '$($number[0])' -and '{0}' -lt '$($number[1])'"
        }
        'less than'
        {
            return "'{0}' -lt '$number'"
        }
        'or less'
        {
            return "'{0}' -le '$number'"
        }
        'less than but not'
        {
            return "'{0}' -lt '$($number[0])' -and '{0}' -gt '$($number[1])'"
        }
        'or less but not'
        {
            return "'{0}' -le '$($number[0])' -and '{0}' -gt '$($number[1])'"
        }
        {$PSItem -match 'or less excluding'}
        {
            return "'{0}' -le '$($number[0])' -and '{0}' -gt '$($number[1])'"
        }
        'and'
        {
            return "'{0}' -ge '$($number[0])' -and '{0}' -le '$($number[1])'"
        }
        {$PSItem -match 'or if the Value Name does not exist'}
        {
            return "'{0}' -match '$($number[0])|ShouldBeAbsent'"
        }
        'through'
        {
            return "{0} -ge '$($number[0])' -and {0} -le '$($number[1])'"
        }
    }
}

<#
    .SYNOPSIS
        Converts a Rule to a hashtable so it can be splatted to other functions

    .PARAMETER InputObject
        The object being converted

    .NOTES
        There are multiple rules in the DNS STIG that enforce the same setting. If a duplicate rule is found
        it is converted to a documentRule
#>
function ConvertTo-HashTable
{
    [CmdletBinding()]
    [OutputType([hashtable])]
    param
    (
        [object] $InputObject
    )

    $hashTable = @{
        Id       = $InputObject.id
        Severity = $InputObject.Severity
        Title    = $InputObject.title
    }

    return $hashTable
}
#endregion
#region Or
<#
    .SYNOPSIS
        Checks if a string is asking for a negative or evaluation. Applies a regular expression against
        the string to look for a known pattern asking for a value to not be equal to one of 2 values.

    .PARAMETER String
        The string data to evaluate.

    .EXAMPLE
        This example returns $true

        Test-StringIsNegativeOr -String "1 or 2 = a Finding"

    .EXAMPLE
        This example returns $false

        Test-StringIsNegativeOr -String "1 or 2 = is not a Finding"

    .NOTES
        Tests if a string such as '1 or 2 = a Finding' is a negative or test.
#>
function Test-StringIsNegativeOr
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    #
    if ($string -match "^(\s*)(\d{1,})(\s*)or(\s*)(\d{1,})(\s*)=(\s*)a(\s*)Finding(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Checks if a string is asking for a positive or evaluation. Applies a regular expression against
        the string to look for a known pattern asking for a value to be equal to one of 2 values.

    .PARAMETER string
        The string data to evaluate.

    .EXAMPLE
        An example

    .NOTES
        # This regex looks for patterns such as "1 (Lock Workstation) or 2 (Force Logoff)"
#>
function Test-StringIsPositiveOr
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    <#
        Optional characters were seperated from the rest of the RegEx because it is a repeating
        pattern. If new characters are discovered in the future, they can be added here and in
        the tests.
    #>
    $optionalCharacter = "(\(|'|"")?"

    $regex = "^(\s*)(\d{1,})(\s*)$optionalCharacter.*$optionalCharacter" +
             "(\s*)or(\s*)(\d{1,})(\s*)$optionalCharacter.*$optionalCharacter(\s*)$"

    if ($string -match $regex)
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of a comparison to a PowerShell code representation.

    .DESCRIPTION
        Using the Abstract Syntax Tree capability of PowerShell, the provided string is broken into
        individual AST Tokens. Those tokens are then combined to form the PowerShell version of the
        English text.

        The output of this function is intended to be added to any STIG rule that is ambiguous due to
        a range of possibilities be valid. The test string is used to determine if a local
        organizational setting is within a valid range according to the STIG.

    .PARAMETER String
        The string to convert

    .EXAMPLE
        This example returns the following comparison test

            -ne '1|2'

        ConvertTo-OrTestString -String '1 or 2 = a Finding' -Operator NotEqual

    .EXAMPLE
        This example returns the following comparison test

            -eq '1|2'

        ConvertTo-OrTestString -String '1 (Lock Workstation) or 2 (Force Logoff)' -Operator Equal

    .NOTES
        General notes
#>
function ConvertTo-OrTestString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String,

        [Parameter(Mandatory = $true)]
        [ValidateSet('Match', 'NotMatch')]
        [String]
        $Operator
    )

    $operatorString = @{
        'Match'    = '-match'
        'NotMatch' = '-notmatch'
    }

    try
    {
        $tokens = [System.Management.Automation.PSParser]::Tokenize($string, [ref]$null)
        $orgSettings = $tokens.Where( {$PSItem.type -eq 'Number' -and $PSItem.Content -notmatch '\dx\d{8}' }).Content
        if ($string -match 'or if the Value Name does not exist')
        {
            $orgSettings += 'ShouldBeAbsent'
        }
        "'{0}' $($operatorString[$Operator]) '$($orgSettings -join "|")'"
    }
    catch
    {
        Throw "Unable to convert $string into test string."
    }
}
#endregion
#region Greater Than

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsGreaterThan -String '14 (or greater)'

    .NOTES
        Sample STIG data would convert
#>
function Test-StringIsGreaterThan
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)Greater(\s*)than(\s*)(\d{1,})(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsGreaterThanOrEqual -String '0x00000032 (50)  (or greater)'

    .NOTES
        Sample STIG data would convert 0x00000032 (50)  (or greater) into '-ge 50'"
#>
function Test-StringIsGreaterThanOrEqual
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)((0x[A-Fa-f0-9]{8}){1})|(\d{1,})(\s*)(\()?or(\s*)greater(\s*)(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsGreaterThanButNot -String 'Greater than 30'

    .NOTES
        Sample STIG data would convert 30 (or greater, but not 100)
#>
function Test-StringIsGreaterThanButNot
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)greater(\s*)than(\s*)(\d{1,})(\s*)(\()?(\s*)but(\s*)not(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}
#endregion
#region Between Two Values
<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsBetweenTwoValues -String '1' and '132'

    .NOTES
        Sample STIG data
#>
function Test-StringIsBetweenTwoValues
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "([3-8][0-9]|9[0-9]|1[0-2][0-9]|13[0-2]|[0-7])")
    {
        $true
    }
    else
    {
        $false
    }
}
<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringHasOneValueOrDoesntExist -String '30' or 'or if the Value Name does not exist'

    .NOTES
        Sample STIG data
#>
function Test-StringHasOneValueOrDoesntExist
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^[0-9] \(or if the Value Name does not exist\)")
    {
        $true
    }
    else
    {
        $false
    }
}
#endregion
#region GreaterThanorEqual
<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsGreaterThanOrEqualToButNot -String '0x00000032 (50)  (or greater)'

    .NOTES
        Sample STIG data
#>
function Test-StringIsGreaterThanOrEqualButNot
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)(\d{1,})(\s*)(\()?(\s*)or(\s*)greater(\s*),(\s*)but(\s*)not(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}
#endregion
#region Less Than
<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThan -String 'is less than "14"'
#>
function Test-StringIsLessThan
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)less(\s*)than(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThanOrEqual -String '"4" logons or less'
#>
function Test-StringIsLessThanOrEqual
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )
    # Turn 0x00000384 (900) (or less) into '-le 900'
    if ($string -match "^((\s*)((0x[A-Fa-f0-9]{8}){1}))?(\s*)(\()?(\d{1,})(\))?(\s*)(\()?or(\s*)less(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThanButNot -String 'Less than 30 (but not 0)'

    .NOTES
        Sample STIG data would convert "Less than 30 (but not 0)" into '$i -lt "30" -and $i -gt 0'
#>
function Test-StringIsLessThanButNot
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    #"$i -lt $value -and -ne $x"

    if ($string -match "^(\s*)less(\s*)than(\s*)(\d{1,})(\s*)(\()?but(\s*)not(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThanOrEqualToButNot -String '30 (or less, but not 0)'

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThanOrEqualToButNot -String '0x0000001e (30) (or less, but not 0)'

    .NOTES
        Sample STIG data would convert 30 (or less, but not 0) into '$i -le "30" -and $i -gt 0'
        Sample STIG data would convert 0x0000001e (30) (or less, but not 0) into '$i -le "30" -and $i -gt 0'
#>
function Test-StringIsLessThanOrEqualButNot
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "^(\s*)(\d{1,})(\s*)(\()?or(\s*)less(\s*),(\s*)but(\s*)not(\s*)(\d{1,})(\))?(\s*)$" -or
        $string -match "(\s*)(\()(\d{1,})(\))(\s*)(\()?or(\s*)less(\s*),(\s*)but(\s*)not(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}
<#
    .SYNOPSIS
        Converts English textual representation of numeric ranges into PowerShell equivalent
        comparison statements.

    .PARAMETER string
        The String to test.

    .EXAMPLE
        This example returns $true

        Test-StringIsLessThanOrEqualExcluding -String '0x0000001e (30) (or less, excluding 0)'

    .NOTES
        Sample STIG data would convert 0x0000001e (30) (or less, excluding 0) into '$i -le "30" -and $i -gt 0'
#>
function Test-StringIsLessThanOrEqualExcluding
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "(\s*)(\()?(\d{1,})(\))?(\s*)(\()?or(\s*)less(\s*),(\s*)excluding(\s*)(\d{1,})(\))?(\s*)$")
    {
        $true
    }
    else
    {
        $false
    }
}
#endregion
#region Multiple Values
<#
    .SYNOPSIS
        Test if the string may contain multiple setting values

    .PARAMETER String
        The string to test

    .EXAMPLE
        This example returns $true

        Test-StringIsMultipleValue -String 'Possible values are orange, lemon, cherry'
#>
function Test-StringIsMultipleValue
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $String
    )

    if ($string -match "(?<=Possible values are ).*")
    {
        $true
    }
    else
    {
        $false
    }
}

<#
    .SYNOPSIS
        Returns the possible setting values

    .PARAMETER String
        The string to test

    .EXAMPLE
        This example returns "{0} -match 'orange|lemon|cherry'""

    ConvertTo-MultipleValue -String 'Possible values are orange, lemon, cherry'
#>
function ConvertTo-MultipleValue
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory)]
        [string[]]
        $String
    )

    $values = [regex]::match( $string, "(?<=Possible values are ).*" ).groups.Value
    $options = $values.replace(', ', '|')

    Write-Verbose "[$($MyInvocation.MyCommand.Name)] Possible Values : $options "

    return $( "'{0}' -match '^($options)$'" )
}
#endregion
#region Security Policy
<#
    .SYNOPSIS
        Selects the string that contains the policy setting and value(s)
#>
function Get-SecurityPolicyString
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"
    $stringMatch = '(If the (value for (the)?)?|(value\s))|(If.*".*" is )'
    $result = ( $checkContent | Select-String -Pattern $stringMatch ) -replace $stringMatch, ''
    # 'V-63427' (Win10) returns multiple matches. This is ensure the only the correct one is returned.
    $result = $result | Where-Object -FilterScript {$PSItem -notmatch 'site is using a password filter'}
    # V-73317 (WinSvr 2016) returns multiple matches, but we want both joined to calculate the range.
    $result = ($result -join " or ").Trim()
    return $result
}

<#
    .SYNOPSIS
        Checks the string for text that indicates a range of acceptable
        acceptable values are allowed by the STIG.
#>
function Test-SecurityPolicyContainsRange
{
    [CmdletBinding()]
    [OutputType([bool])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $string = Get-SecurityPolicyString -CheckContent $checkContent
    $string = Get-TestStringTokenList -String $string

    # This array is joined into an or '|' before being evaluated
    $matchList = @(
        '(?:is not set to )(?!(?:(a )other than)).*(?:this is a finding\.)',
        '(the value is .*this is a finding)',
        '((enabled|not(?: enabled)?) this is a finding)',
        '((column .*)|(for this option .*)this is a finding)'
    )

    if ( $string -match ($matchList -join '|') )
    {
        return $false
    }

    return $true
}

<#
    .SYNOPSIS
        Converts the Check-Content string into a PowerShell comparison string that can validate
        user input to organizational values.
#>
function Get-SecurityPolicyOrganizationValueTestString
{
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    Write-Verbose "[$($MyInvocation.MyCommand.Name)]"

    $stringBase = Get-SecurityPolicyString -CheckContent $CheckContent
    $string = Get-TestStringTokenList -String $stringBase -CommandTokens
    $settings = Get-TestStringTokenList -String $stringBase -StringTokens

    $reverse = @{
        'lt' = 'ge';
        'le' = 'gt';
        'gt' = 'le';
        'ge' = 'lt';
        'eq' = 'ne';
        'ne' = 'eq'
    }

    # The index string to add to the comparison for use in composite formatting.
    $indexString = "'{0}'"
    # The variable needs to be strongly typed for the indexing to work properly, when a single operator is found.
    # If not strongly typed, a single operator will return indexed characters.
    [string[]] $operators = @()
    # Some of the sentence structure is inverted, so this flag will realign the sentence structure so that that range operator
    # Is always before the eq|ne operators.
    $invertAdjective = $false
    # Some of the ranges have exclusions, so the comparison operator should not be inverted and this flag controls that.
    $excludeSecondAdjective = $false

    switch ($string)
    {
        {$string -match '^is set to'}
        {
            $operators = 'eq'
        }
        {$string -match '^is less than(?!.*excluding)'}
        {
            $operators = 'lt'; continue
        }
        {$string -match '^is less than(?=.*excluding)'}
        {
            $operators = 'lt', 'or', 'eq'; $excludeSecondAdjective = $true; continue
        }
        {$string -match '^is greater than(?!.*(excluding|is set))'}
        {
            $operators = 'gt'; continue
        }
        {$string -match '^is greater than.*(?=is set)'}
        {
            $operators = 'gt', 'and', 'eq'; continue
        }
        # The InvertAdjective changes the string to read 'is more than or' to move the equal to the second position like everything else.
        {$string -match '^is or (more|greater) than'}
        {
            $operators = 'gt', 'and', 'eq'; $invertAdjective = $true; continue
        }
        {$string -match '^is not set to a other than'}
        {
            $operators = 'eq'
        }
    }

    # Since the sentence was inverted, the value positions need to be inverted as well.
    if ($invertAdjective)
    {
        $firstValue = $settings[2]
        $secondValue = $settings[1]
    }
    else
    {
        $firstValue = $settings[1]
        $secondValue = $settings[2]
    }

    # Some settings are negated with the string 'this is a finding, so invert the comparison operators if the check is negated.
    if ($string -match 'this is a finding')
    {
        # If a string contains and/or build that into the test string operators
        if ($operators.count -gt '1')
        {
            # Some settings have values that need to be excluded from a range, so do not invert that operator
            if ($excludeSecondAdjective)
            {
                "$indexString -$($reverse[$operators[0]]) '$firstValue' -$($operators[1]) $indexString -$($operators[2]) '$secondValue'"
            }
            else
            {
                "$indexString -$($reverse[$operators[0]]) '$firstValue' -$($operators[1]) $indexString -$($reverse[$operators[2]]) '$secondValue'"
            }
        }
        else
        {
            "$indexString -$($reverse[$operators[0]]) '$firstValue'"
        }
    }
    else
    {
        "$indexString -$operators '$firstValue'"
    }
}
#endregion
