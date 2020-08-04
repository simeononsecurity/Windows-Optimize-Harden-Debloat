# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# These are the registry types that are accepted by the registry DSC resource
data regularExpression
{
    ConvertFrom-StringData -StringData @'

        blankString = \\(Blank\\)
        enabledOrDisabled = Enable(d)?|Disable(d)?

        # Match a exactly one ( the first ) hexcode in a string
        hexCode = \\b(0x[A-Fa-f0-9]{8}){1}\\b

        # Looks for an integer but is not hex
        leadingIntegerUnbound = \\b([0-9]{1,})\\b

        # The registry hive is not provided in a consistant format, so the search pattern needs
        # To account for optional character ranges
        registryHive = (Registry)?\\s?Hive\\s?:\\s*?(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER)

        #registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)\\w+(\\\\)?

        registryPath      = ((Registry)?\\s*(Path|SubKey)\\s*:\\s*|^\\\\SOFTWARE)(\\\\)?\\w+(\\\\)(\\w+(\\\\)?|\\sP)

        registryEntryType = Type\\s?:\\s*?REG_(SZ|BINARY|DWORD|QWORD|MULTI_SZ|EXPAND_SZ)(\\s{1,}|$)

        registryValueName = ^\\s*?Value\\s*?Name\\s*?:

        registryValueData = ^\\s*?Value\\s*?:
        # Extracts multi string values
        MultiStringNamedPipe = (?m)(^)(System|Software)(.+)$

        # Or is in a word boundary since it is a common pattern
        registryValueRange = (?<![\\w\\d])but|\\bor\\b|through|and|Possible values(?![\\w\\d])

        # This is need validate that a value is still a string even if it contains a number
        hardenUncPathValues = (RequireMutualAuthentication|RequireIntegrity)
'@
}

data dscRegistryValueType
{
    ConvertFrom-StringData -StringData @'
        REG_SZ         = String
        REG_BINARY     = Binary
        REG_DWORD      = Dword
        REG_QWORD      = Qword
        REG_MULTI_SZ   = MultiString
        REG_EXPAND_SZ  = ExpandableString
        Does Not Exist = Does Not Exist
        DWORD          = Dword
        Disabled       = Dword
        Enabled        = Dword
'@
}
