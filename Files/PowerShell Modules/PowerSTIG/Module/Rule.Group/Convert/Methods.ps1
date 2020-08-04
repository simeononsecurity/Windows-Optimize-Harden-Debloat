# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
#region Method Functions
<#
    .SYNOPSIS
        Retrieves the Group Details (GroupName and MembersToExclude) from the
        STIG rule check-content
    .PARAMETER CheckContent
        Specifies the check-content element in the xccdf
#>
function Get-GroupDetail
{
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [string[]]
        $CheckContent
    )

    $templateFile = "$PSScriptRoot\Template.GroupDetail.txt"
    $result = $checkContent | ConvertFrom-String -TemplateFile $templateFile

    return $result
}
#endregion
