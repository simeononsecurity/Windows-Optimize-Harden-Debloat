# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    Instructions:  Use this file to add/update/delete regsitry expressions that are used accross 
    multiple technologies files that are considered commonly used.  Enure expressions are listed
    from MOST Restrive to LEAST Restrictive, similar to exception handling.  Also, ensure only
    UNIQUE Keys are used in each hashtable to orevent errors and conflicts.
#>

$global:SingleLineRegistryPath += [ordered]@{
    Office1 = [ordered]@{
        Match  = 'outlook\\security'
        Select = '((HKLM|HKCU).*\\security)'
    }
    # Added for Outlook Stig V-17761.b
    Office2 = [ordered]@{ 
        Match  = 'value for hkcu.*Message\sPlain\sFormat\sMime'
        Select = '(HKCU).*(?<=me)'
    }
    # Added for Excel Stig V-71029
    Office3 = [ordered]@{ 
        Match  = '\\security\\filevalidation\\'
        Select = '(HKCU).*(?<=ion)'
    }
}

$global:SingleLineRegistryValueName += [ordered]@{
    Office1 = @{
        Match  = 'If the REG_DWORD'
        Select = '((?<=for\s")(.*)(?<="))'
    }
    # Added for Outlook Stig V-17761.b
    Office2 = @{ 
        Match  = 'Message Plain Format Mime'
        Select = '((?<=il\\)(.*)(?<=e\s))'
    }
    # Added for Outlook Stig V-17575
    Office3 = @{ 
        Match  = 'Configure trusted add-ins'
        Select = '(?<=ty\\).*(?=\sIn)'
    }
    # Added for Outlook Stig V-17761.a
    Office4 = @{ 
        Match  = 'a value of between'
        Select = '((?<=gs\\)(.*)(?<=Len))'
    }
    # Added for Outlook Stig V-17774 and V-17775
    Office5 = @{ 
        Match  = 'FileExtensionsRemoveLevel'
        Select = '(?<=the registry value\s.)(.*)(?=.\We)'
    }
    # Added for Outlook Stig V-17733
    Office6 = [ordered]@{ 
        Match  = 'If the.+(registry key exist)'
        Select = '(?<=ty\\).*(?=\sC)'
    }
    # Added for Excel Stig V-71015 and V-71027
    Office7 = [ordered]@{ 
        Match  = 'Criteria: If the value of '
        Select = '(?<=Criteria: If the value of )([^\s]+)'
    }
    Office8 = [ordered]@{ 
        Match  = 'Criteria: If the value '
        Select = '(?<=Criteria: If the value\s)([^\s]+)'
    }
}

$global:SingleLineRegistryValueType += [ordered]@{
    Office1 = @{
        Select = '((?<=If the\s)(.*)(?<=DWORD))'
    }
    # Added for Outlook Stig V-17575
    Office2 = @{ 
        Select = '(?<=\sto\s).*"'
    }
}

$global:SingleLineRegistryValueData += [ordered]@{
    # Added for Outlook Stig V-17776
    Office1 = @{ 
        Match  = 'If the value PublishCalendarDetailsPolicy'
        Select = '((?<=is\s)(.*)(?=\sor))'
    }
    # Added for Outlook Stig V-17761.a
    Office2 = @{ 
        Match  = 'a value of between'
        Select = '(?<=between\s)(.*)(?<=\s)'
    }
}
