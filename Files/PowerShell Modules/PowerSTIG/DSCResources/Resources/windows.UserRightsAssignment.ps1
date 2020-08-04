# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type UserRightRule

$domainGroupTranslation = @{
    'Administrators'            = 'Builtin\Administrators'
    'Auditors'                  = '{0}\auditors'
    'Authenticated Users'       = 'Authenticated Users'
    'Domain Admins'             = '{0}\Domain Admins'
    'Guests'                    = 'Guests'
    'Local Service'             = 'NT Authority\Local Service'
    'Network Service'           = 'NT Authority\Network Service'
    'NT Service\WdiServiceHost' = 'NT Service\WdiServiceHost'
    'NULL'                      = ''
    'Security'                  = '{0}\security'
    'Service'                   = 'Service'
    'Window Manager\Window Manager Group' = 'Window Manager\Window Manager Group'
}

$forestGroupTranslation = @{
    'Enterprise Admins'         = '{0}\Enterprise Admins'
    'Schema Admins'             = '{0}\Schema Admins'
}

if ($DomainName -and $ForestName)
{
    # This requires a local forest and/or domain name to be injected to ensure a valid account name.
    $DomainName = PowerStig\Get-DomainName -DomainName $DomainName -Format NetbiosName
    $ForestName = PowerStig\Get-DomainName -ForestName $ForestName -Format NetbiosName

    foreach ($rule in $rules)
    {
        Write-Verbose -Message $rule
        $identitySplit = $rule.Identity -split ","
        [System.Collections.ArrayList] $identityList = @()

        foreach ($identity in $identitySplit)
        {
            if ($domainGroupTranslation.Contains($identity))
            {
                [void] $identityList.Add($domainGroupTranslation.$identity -f $DomainName )
            }
            elseif ($forestGroupTranslation.Contains($identity))
            {
                [void] $identityList.Add($forestGroupTranslation.$identity -f $ForestName )
            }
            # Default to adding the identify as provided for any non-default identities.
            else
            {
                [void] $identityList.Add($identity)
            }
        }

        UserRightsAssignment (Get-ResourceTitle -Rule $rule)
        {
            Policy   = ($rule.DisplayName -replace " ", "_")
            Identity = $identityList
            Force    = [bool] $rule.Force
        }
    }
}
else
{
    foreach ($rule in $rules)
    {
        Write-Warning -Message "$($rule.id) not compiled to mof because DomainName and ForestName were not specified"
    }
}
