# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

data regularExpression
{
    ConvertFrom-StringData -StringData @'
        mimeTypeAbsent  = verify MIME types for OS shell program extensions have been removed
        mimeType        = (?<=)^[.].+(?=)

'@
}
