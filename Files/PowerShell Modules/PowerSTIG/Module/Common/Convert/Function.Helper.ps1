# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    .SYNOPSIS
        Appends the next letter in the alphabet to the ID to handle rules that enforce multiple settings
#>
function Get-AvailableId
{
    [CmdletBinding()]
    [OutputType([string])]
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Id
    )

    $usedId = $global:stigSettings | Where-Object -FilterScript { $PSItem.Id -match $ID } |
            Sort-Object -Property Id

    if ( $null -eq $usedId )
    {
        return $id
    }
    else
    {
        $startInt = 96
        # 97 is the ascii char 'a', lets start with 96 so the second rule with the same id gets appended with a letter

        $appendLetterInt = $startInt + $usedId.count

        return "$id.$([char]$appendLetterInt)"
    }
}
