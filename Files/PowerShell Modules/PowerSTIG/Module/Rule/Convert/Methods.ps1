#region Method Functions

<#
    .SYNOPSIS
        Checks for Html encoded char

    .PARAMETER CheckString
        The string to convert.
#>
function Test-HtmlEncoding
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $CheckString
    )

    if ( $CheckString -match '&\w+;' )
    {
        return $true
    }
    else
    {
        return $false
    }
}

<#
    .SYNOPSIS
        Converts Html encoded strings back in the ascii char

    .PARAMETER CheckString
        The string to convert.
#>
function ConvertFrom-HtmlEncoding
{
    [OutputType([String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [String]
        $CheckString
    )

    return [System.Web.HttpUtility]::HtmlDecode( $CheckString )
}

<#
    .SYNOPSIS
        Tests the results of ConvertTo-*Rule functions for duplicates.  The DNS STIG has multiple duplicates but we only
        need to account for them once.  If a duplicate is detected we will convert that rule to a document rule.

    .PARAMETER ReffernceObject
        The list of Stigs objects to compare to.

    .PARAMETER DifferenceObject
        The newly created object to verify is not a duplicate.

    .NOTES
        General notes
#>
function Test-DuplicateRule
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowNull()]
        [object]
        $ReferenceObject,

        [Parameter(Mandatory = $true)]
        [object]
        $DifferenceObject
    )

    $ruleType = $DifferenceObject.GetType().Name
    $ruleType = $ruleType.Replace("Convert", "")
    $baseRule = [Rule]::New()

    $referenceProperties = ($baseRule | Get-Member -MemberType Property).Name
    $differenceProperties = ($DifferenceObject | Get-Member -MemberType Property).Name

    $propertyList = (Compare-Object -ReferenceObject $referenceProperties -DifferenceObject $differenceProperties).InputObject
    $referenceRules = $ReferenceObject | Where-Object {$PsItem.GetType().Name  -eq $ruletype}

    foreach ($rule in $referenceRules)
    {
        $results = @()

        foreach ($propertyName in $PropertyList)
        {
            $results += $rule.$propertyName -eq $DifferenceObject.$propertyName
        }

        if ($results -notcontains $false)
        {
            return $rule.id
        }
    }
    # If the code made it this far a duplicate does not exist and we return $null
    return $null
}

<#
    .SYNOPSIS
        Looks in $global:stigSettings for existing rules

    .NOTES
        Some rules in the STIG enforce multiple settings. This function will test for
        this scenario to so we can act upon it later.
#>
function Test-ExistingRule
{
    [CmdletBinding()]
    [OutputType([Boolean])]
    param
    (
        [Parameter()]
        [object]
        $RuleCollection,

        [Parameter()]
        [object]
        $NewRule
    )

    $IdExist = $RuleCollection | Where-Object {$PSItem.Id -eq $NewRule.Id}

    return $IdExist.id -eq $NewRule.id
}
#endregion
