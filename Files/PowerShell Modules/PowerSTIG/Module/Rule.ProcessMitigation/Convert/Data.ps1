# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

data regularExpression
{
    ConvertFrom-StringData -StringData @'
        ColonSpaceOn                    = :\\sON
        EnableColon                     = Enable:
        IfTheStatusOf                   = If\\sthe\\sstatus\\sof
        IfTheStatusOfIsOff              = If\\sthe\\sstatus\\sof[\\s\\S]*?\\sis\\s"OFF"[\\s\\S]*this\\sis\\sa\\sfinding
        NotHaveAStatusOfOn              = If\\sthe\\sfollowing\\smitigations\\sdo\\snot\\shave\\sa\\sstatus\\sof\\s"ON"
        TextBetweenDoubleQuoteAndColon  = "[\\s\\S]*?:
        TextBetweenColonAndDoubleQuote  = :[\\s\\S]*?"
'@
}
