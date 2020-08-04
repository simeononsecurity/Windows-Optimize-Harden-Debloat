# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type IisLoggingRule

if ($rules)
{
    $logFlags = Get-UniqueStringArray -InputObject $rules.LogFlags -AsString
    $logFormat = Get-UniqueString -InputObject $rules.LogFormat
    $logTargetW3C = Get-UniqueString -InputObject $rules.LogTargetW3C
    $logCustomField = Get-LogCustomField -LogCustomField $rules.LogCustomFieldEntry.Entry -Resource 'xIisLogging'

    $resourceTitle = "[$($rules.id -join ' ')]"

    $scriptBlock = [scriptblock]::Create("
        xIisLogging '$resourceTitle'
        {
            LogPath         = '$LogPath'
            LogFlags        = @($logFlags)
            LogFormat       = '$logFormat'
            LogTargetW3C    = '$logTargetW3C'
            LogCustomFields = @($logCustomField)
        }"
    )

    & $scriptBlock
}
