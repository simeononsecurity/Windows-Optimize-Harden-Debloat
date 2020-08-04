# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\Module\STIG\STIG.psm1

$pathList = @(
    "$PSScriptRoot\Module\Stig"
)
foreach ($supportFile in (Get-ChildItem -Path $pathList -File -Filter '*.ps1'))
{
    Write-Verbose "Loading $($supportFile.FullName)"
    . $supportFile.FullName
}

Export-ModuleMember -Function @(
    'Get-DomainName',
    'Get-Stig',
    'New-StigCheckList',
    'Get-StigRuleList',
    'Get-StigVersionNumber',
    'Get-PowerStigFilelist',
    'Split-BenchmarkId'
)
