# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

data regularExpression
{
    ConvertFrom-StringData -StringData @'
        customFields            = >>
        logFlags                = (?<=(")?Select Fields(")?, verify at a minimum the following fields are checked:).+(?=\.)
        logFormat               = Verify the "Format:" under "Log File" is configured to
        logPeriod               = Verify a schedule is configured to rollover log files
        logTargetW3c            = Under Log Event Destination, verify the
        standardFieldEntries    = "([^"]*)"
        standardFields          = (?<=Under "Standard Fields",).+
'@
}

data logflagsConstant
{
    ConvertFrom-StringData -StringData @'
        Client IP Address = ClientIP
        Date              = Date
        Method            = Method
        Protocol Status   = HttpStatus
        Referrer          = Referer
        and Referrer      = Referer
        Time              = Time
        URI Query         = UriQuery
        User Agent        = UserAgent
        User Name         = UserName
'@
}
