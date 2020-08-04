# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
# Header

<#
    .SYNOPSIS
        Singleton class to support variable filter and parse methods in FileContentRule
    .DESCRIPTION
        The FileContentType is used to extend filter and parse logic for diiferent
        FileContentRules without modifing existing filtering and parsing logic
    .PARAMETER Instance
        Maintains a single instance of the class object
#>
class FileContentType
{
    static [FileContentType] $Instance
    #region Constructor
    hidden FileContentType () {}

     #region Methods

     <#
        .SYNOPSIS
            Returns an instance of the class
        .DESCRIPTION
            Gets or sets a single instance of the FileContentType
            for use in the FileContentRule
    #>

     static [FileContentType] GetInstance()
     {
         if ([FileContentType]::Instance -eq $null)
         {
             [FileContentType]::Instance = [FileContentType]::new()
         }
         return [FileContentType]::Instance
     }

    <#
        .SYNOPSIS
            Loads and applies specific filtering and parsing rules
        .DESCRIPTION
            When Key-Value settings are located in a rule, the format
            of Key-Value pairs differ between technologies, this method
            supports a unique filter and parsing strategy for the rule
        .PARAMETER matchResult
            The key-value settings from the check-content element in the xccdf
    #>

    [pscustomobject] ProcessMatches ( [psobject] $matchResult )
    {
        $exclude = @($MyInvocation.MyCommand.Name,'Template.*.txt')
        $supportFileList = Get-ChildItem -Path $PSScriptRoot -Exclude $exclude -Recurse -Include "*.$($global:stigXccdfName).*"
        foreach ($supportFile in $supportFileList)
        {
            Write-Verbose "Loading $($supportFile.FullName)"
            . $supportFile.FullName
        }

        $filtered = Get-FilteredItem -MatchResult $matchResult
        if ($filtered)
        {
            return $filtered;
        }
        else
        {
            return $null
        }
    }
}
