# PowerSTIG Archive log file

* I have talked a little bit about starting to modify the xccdf files to fix minor issues in the content the DISA provides.
* The initial idea was to manually update the xccdf and keep a record of the change in a markdown file. ID::OldText::NewText
* I realized that this is not a great solution, due to not being 100% sure what the original text was.
* Let's automate

## Challenge

* STIGs are not written in a consistent format and cannot be repeatedly parsed correctly.
* No easy way to fix Spelling \ Formatting issues.

## Purposed solution

* Take the original idea and automate it now before we make a bunch of changes that we have to undo later.
* The change log is now an active file that is used during the parsing process.

## How it works

1. The code looks for a .log file with the same full path as the xccdf.
1. Each line is in the following format ID::OldText::NewText
    1. Multiple entries per rule are supported
    1. The asterisk "*" can be used to replace everything in the check-content
1. The log content is converted into a hashtable
1. Before a rule is processed, the check-content string is updated using a replace OldText > NewText.
1. The rule is parsed and returned
1. The RawString is then updated to undo the log file change NewText > OldText.

This allows us to inject the rule intent without having to dig into the xml or update the parser.
We have most of the general patterns ironed out and now we are just dealing with random formatting\ spelling charges.
We need to take the time to determine when the change needs to be made, because we don't necessarily want to end up with a log file entry for each rule either.

## HardCodedRule Automation

* Rules can be Hard Coded with Check Content replacement using the log file, leveraging the replace all feature "*".
* In order to generate a HardCodedRule log file entry, the **Get-HardCodedRuleLogFileEntry** function can be leveraged.
* Example Entries:
  * Single Rule:
    * **V-1000::*::HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Name = 'Web-Ftp-Server'; Ensure = 'Absent'}**
  * Split Rule would include the structure from the Single Rule with the **\<splitRule>** delimiter appended to the end of the string:
    * **...\<splitRule>HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Name = $null; Ensure = 'Absent'}**
* Note: If a user needs to supply a value, the hashtable DscResource parameter should be set to $null, like the Split Rule example above.
* For more complex Hard Coded Rule examples, refer to the [wiki](https://github.com/Microsoft/PowerStig/wiki/HardCodedRule)

```PowerShell
PS C:\> Import-Module .\PowerStig.Convert.psm1
PS C:\> Get-HardCodedRuleLogFileEntry -RuleId V-1000 -RuleType WindowsFeatureRule
V-1000::*::HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Ensure = $null; Name = $null}
PS C:\> # Creating a split rule with WindowsFeatureRule and FileContentRule
PS C:\> Get-HardCodedRuleLogFileEntry -RuleId V-1000 -RuleType WindowsFeatureRule, FileContentRule
V-1000::*::HardCodedRule(WindowsFeatureRule)@{DscResource = 'WindowsFeature'; Ensure = $null; Name = $null}<splitRule>HardCodedRule(FileContentRule)@{DscResource = 'ReplaceText'; Key = $null; Value = $null}
```
