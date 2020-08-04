# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type IisLoggingRule

if ($rules)
{
    $logFlags = Get-UniqueStringArray -InputObject $rules.LogFlags -AsString
    $logFormat = Get-UniqueString -InputObject $rules.LogFormat
    $logPeriod = Get-UniqueString -InputObject $rules.LogPeriod
    $logTargetW3C = Get-UniqueString -InputObject $rules.LogTargetW3C
    $logCustomField = Get-LogCustomField -LogCustomField $rules.LogCustomFieldEntry.Entry -Resource 'xWebSite'

    foreach ($website in $WebsiteName)
    {
        $resourceTitle = "[$($rules.id -join ' ')]$website"

        if ($null -eq $logPeriod)
        {
            $scriptBlock = [scriptblock]::Create("
                xWebSite '$resourceTitle'
                {
                    Name            = '$website'
                    LogFlags        = @($logFlags)
                    LogFormat       = '$logFormat'
                    LogTargetW3C    = '$logTargetW3C'
                    LogCustomFields = @($logCustomField)
                }"
            )
        }
        else
        {
            $scriptBlock = [scriptblock]::Create("
                xWebSite '$resourceTitle'
                {
                    Name            = '$website'
                    LogFlags        = @($logFlags)
                    LogFormat       = '$logFormat'
                    LogPeriod       = '$logPeriod'
                    LogTargetW3C    = '$logTargetW3C'
                    LogCustomFields = @($logCustomField)
                }"
            )
        }

        & $scriptBlock
    }
}
