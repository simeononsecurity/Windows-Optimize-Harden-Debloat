# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

$rules = $stig.RuleList | Select-Rule -Type PermissionRule

foreach ($rule in $rules)
{
    # Determine PermissionRule type and handle
    switch ($rule.dscresource)
    {
        'RegistryAccessEntry'
        {
            $ruleForce = $null
            [void][bool]::TryParse($rule.Force, [ref]$ruleForce)
            RegistryAccessEntry (Get-ResourceTitle -Rule $rule)
            {
                Path = $rule.Path
                Force = $ruleForce
                AccessControlList = $(

                    foreach ($acentry in $rule.AccessControlEntry.Entry)
                    {
                        $aceEntryForcePrincipal = $null
                        [void][bool]::TryParse($acentry.ForcePrincipal, [ref]$aceEntryForcePrincipal)
                        AccessControlList
                        {
                            Principal = $acentry.Principal
                            ForcePrincipal = $aceEntryForcePrincipal
                            AccessControlEntry = @(
                                AccessControlEntry
                                {
                                    AccessControlType = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Type)))
                                        {
                                            $acentry.Type
                                        }
                                        else
                                        {
                                            'Allow'
                                        }
                                    )
                                    Inheritance = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Inheritance)))
                                        {
                                            $acentry.Inheritance
                                        }
                                        else
                                        {
                                            'This Key and Subkeys'
                                        }
                                    )
                                    Rights = $acentry.Rights.Split(',')
                                    Ensure = 'Present'
                                }
                            )
                        }
                    }
                )
            }
            break
        }
        'NTFSAccessEntry'
        {
            $ruleForce = $null
            [void][bool]::TryParse($rule.Force, [ref]$ruleForce)
            NTFSAccessEntry (Get-ResourceTitle -Rule $rule)
            {
                Path = $rule.Path
                Force = $ruleForce
                AccessControlList = $(
                    foreach ($acentry in $rule.AccessControlEntry.Entry)
                    {
                        $aceEntryForcePrincipal = $null
                        [void][bool]::TryParse($acentry.ForcePrincipal, [ref]$aceEntryForcePrincipal)
                        NTFSAccessControlList
                        {
                            Principal = $acentry.Principal
                            ForcePrincipal = $aceEntryForcePrincipal
                            AccessControlEntry = @(
                                NTFSAccessControlEntry
                                {
                                    AccessControlType = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Type)))
                                        {
                                            $acentry.Type
                                        }
                                        else
                                        {
                                            'Allow'
                                        }
                                    )
                                    Inheritance = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Inheritance)))
                                        {
                                            $acentry.Inheritance
                                        }
                                        else
                                        {
                                            'This folder only'
                                        }
                                    )
                                    FileSystemRights = $acentry.Rights.Split(',')
                                    Ensure = 'Present'
                                }
                            )
                        }
                    }
                )
            }
            break
        }
        'FileSystemAuditRuleEntry'
        {
            $ruleForce = $null
            [void][bool]::TryParse($rule.Force, [ref]$ruleForce)
            FileSystemAuditRuleEntry (Get-ResourceTitle -Rule $rule)
            {
                Path          = $rule.Path
                Force         = $ruleForce
                AuditRuleList = @(
                    foreach ($acentry in $rule.AccessControlEntry.Entry)
                    {
                        FileSystemAuditRuleList
                        {
                            Principal = $acentry.Principal
                            ForcePrincipal = $false
                            AuditRuleEntry = @(
                                FileSystemAuditRule
                                {
                                    AuditFlags = 'Success'
                                    FileSystemRights = $acentry.Rights.Split(',')
                                    Inheritance = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Inheritance)))
                                        {
                                            $acentry.Inheritance
                                        }
                                        else
                                        {
                                            'This folder only'
                                        }
                                    )
                                    Ensure = 'Present'
                                }
                                FileSystemAuditRule
                                {
                                    AuditFlags = 'Failure'
                                    FileSystemRights = $acentry.Rights.Split(',')
                                    Inheritance = $(
                                        if (-not ([string]::IsNullOrEmpty($acentry.Inheritance)))
                                        {
                                            $acentry.Inheritance
                                        }
                                        else
                                        {
                                            'This folder only'
                                        }
                                    )
                                    Ensure = 'Present'
                                }
                            )
                        }
                    }
                )
            }
            break
        }
    }
}
