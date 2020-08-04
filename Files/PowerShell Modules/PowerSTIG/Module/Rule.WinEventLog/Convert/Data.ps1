# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This is used to centralize the regEx patterns
data regularExpression
{
    ConvertFrom-StringData -StringData @'
        WinEventLogPath = Logs\\\\Microsoft\\\\Windows
'@
}
