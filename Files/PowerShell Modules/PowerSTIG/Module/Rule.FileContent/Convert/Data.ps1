data fileContentRegex
{
    ConvertFrom-StringData -StringData @'
        BetweenAllQuotes           = ("|{0}|{1}|{2})[\\s\\S]*?("|{0}|{1}|{2})
        RegexToRemove              = "|{0}|{1}|{2}
        TwoTo5CapitalLetters       = [A-Z]{2,5}
        CapitalsEndWithSpaceOrDot5 = [A-Z,1-9]{2,5}(\\s|\\.)
        CapitalsEndWithSpaceOrDot4 = [A-Z,1-9]{2,4}(\\s|\\.)
        RemoveAnyNonWordCharacter  = \\W
'@
}
