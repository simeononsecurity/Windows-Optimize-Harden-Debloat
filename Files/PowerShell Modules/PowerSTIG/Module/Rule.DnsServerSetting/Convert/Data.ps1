# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This is used to centralize the regEx patterns
data regularExpression
{
    ConvertFrom-StringData -StringData @'
        allEvents = \\"All\\sevents\\"
        nonLetters = [^a-zA-Z ]
        textBetweenTheTab = the\\s(?s)(.*)tab\\.
'@
}

data dnsServerSetting
{
    ConvertFrom-StringData -StringData @'
        Event Logging = EventLogLevel
        Forwarders    = NoRecursion
'@
}
