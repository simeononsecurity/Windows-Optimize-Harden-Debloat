# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

<#
    Instructions:  Use this file to add/update/delete regsitry expressions that are used accross 
    multiple technologies files that are considered commonly used.  Ensure expressions are listed
    from MOST Restrive to LEAST Restrictive, similar to exception handling.  Also, ensure only
    UNIQUE Keys are used in each hashtable to prevent errors and conflicts.
#>

$global:SingleLineRegistryValueName += [ordered]@{
    McAfee1 = @{
        Match  = 'Wow6432Node\\McAfee'
        Select = '(?<=If the value (of|for)\s)(\w+)'
    }
    McAfee2 = @{
        Match  = 'Wow6432Node\\McAfee'
        Select = '(?<=If the value\s)(\w+)'
    }
    McAfee3 = @{
        Match  = 'Wow6432Node\\McAfee'
        Select = '(?<=\s\sIf the\s)(\w+)'
    }
    McAfee4 = @{
        Match  = 'Wow6432Node\\McAfee'
        Select = '(?<=Criteria:\sIf the\s.)(\w+)'
    }
}

$global:SingleLineRegistryValueData += [ordered]@{
    McAfee1 = @{
        Select = '(?<=\sis\sREG_DWORD\s=\s)(\d+)'
    }
    McAfee2 = @{
        Select = '(?<=does not have a value of\s)(\d+)'
    }
    McAfee3 = @{
        Select = '(?<=\sis not\s)(\d+)'
    }
    McAfee4 = @{
        Select = '(?<=0x000001a0\s\()(\d+)'
    }
    McAfee5 = @{
        Select = '(?<=is not set to ")(\d+)'
    }
    McAfee6 = @{
        Select = '(?<=does not have a value of\s)(\d+)'
    }
    McAfee7 = @{
        Select = '(?<=If the value of\s)\w+\sis\s(\d+)'
    }
    McAfee8 = @{
        Select = ' (?<=If the value\s)\w+\sis\s(\d+)'
    }
}
