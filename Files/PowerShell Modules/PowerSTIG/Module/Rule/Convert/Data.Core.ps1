# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    Instructions:  Use this file to add/update/delete regsitry expressions that are used accross 
    multiple technologies files that are considered commonly used.  Enure expressions are listed
    from MOST Restrive to LEAST Restrictive, similar to exception handling.  Also, ensure only
    UNIQUE Keys are used in each hashtable to prevent errors and conflicts.  Within each table there
    can be a single key for Contains, Match, and Select.  These keys match functions in the refactored
    Functions.SingleLine.ps1 script in the RegistryRule module.  Example: See Data.Office.ps1
#>
$global:SingleLineRegistryPath += [ordered]@{
    Criteria = [ordered]@{
        Contains = 'Criteria:'
        After    = [ordered]@{
            Match  = '((HKLM|HKCU).*(?=Criteria:))'
            Select = '((HKLM|HKCU).*(?=Criteria:))'
        }
        Before = [ordered]@{
            Match = 'Criteria:.*(HKLM|HKCU)'
            Select = '((HKLM|HKCU).*(?=\sis))'
        }
    }
    Verify = [ordered]@{
        Contains = 'Verify'
        Select   = '((HKLM|HKCU).*(?=Verify))'
    }
    Root = [ordered]@{
        Match    = '(HKCU|HKLM|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)\\'
        Select   = '((HKLM|HKCU|HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*)'
    }
}

$global:SingleLineRegistryValueName += [ordered]@{
    One   = @{
        Select = '(?<=If the value(\s*)?((for( )?)?)").*(")?((?=is.*R)|(?=does not exist))'
    }
    Two   = [ordered]@{
        Match  = 'If the.+(registry key does not exist)'
        Select = '"[\s\S]*?"'
    }
    Three = @{
        Select = '(?<=If the value of\s")(.*)(?="\s.*R)|(?=does not exist)'
    }
    Four  = [ordered]@{
        Match  = 'a value of between'
        Select = '((?<=gs\\)(.*)(?<=Len))'
    }
    Five  = @{
        Select = '((?<=If the value\s)(.*)(?=is\sR))'
    }
    Six   = [ordered]@{
        Match  = 'the policy value'
        Select = '(?<=")(.*)(?="\sis)'
    }
    Seven = @{
        Select = '((?<=for\s).*)'
    }
    Eight = @{
        Select = '(?<=filevalidation\\).*(?=\sis\sset\sto)'
    }
}

$global:SingleLineRegistryValueType += [ordered]@{
    One   = @{
        Select = '(?<={0}(") is not).*='
    }
    Two   = @{
        Select = '({0}"?\sis (?!not))(.*=)'
        Group  = 2
    }
    Three = @{
        Select = '(?<=Verify\sa).*(?=value\sof)'
    }
    Four  = @{
        Select = 'registry key exists and the([\s\S]*?)value'
        Group  = 1
    }
    Five  = @{
        Select = '(?<={0}" is set to ).*"'
    }
    Six   = @{
        Select = '((hkcu|hklm).*\sis\s(.*)=)'
        Group  = 3
    }
    Seven   = @{
        Select = '(?<={0}"\s)(does not exist)'
    }
}

$global:SingleLineRegistryValueData += [ordered]@{
    One   = @{
        Select = '(?<={0})(\s*)?=.*(?=(,|\())'
    }
    Two   = @{
        Select = '((?<=value\sof).*(?=for))'
    }
    Three = @{
        Select = '((?<=set\sto).*(?=\(true\)))' 
    }
    Four  = @{
        Select = "((?<=is\sset\sto\s)(`'|`")).*(?=(`'|`"))"
    }
    Five  = @{
        Select = "(?<={0}\s=).*"
    }
}
