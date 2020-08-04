# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This is used to centralize the regEx patterns

data regularExpression
{
    ConvertFrom-StringData -StringData @'
        WindowsFeatureName = Get-Windows(?:Optional)?Feature\\s*(?:-Online\\s*)?(?:-Name|\\|\\s*Where\\s*(?:Feature)?Name\\s*-eq)\\s*(?'featureName'(\\w*(-?))+)
        FeatureNameEquals = FeatureName\\s-eq\\s*\\S*
        FeatureNameSpaceColon = FeatureName\\s\\:\\s\\S*
        IfTheApplicationExists = If the [\\s\\S]*?application exists
        WebDavPublishingFeature = ((W|w)eb(DAV|(D|d)av) (A|a)uthoring)|(WebDAV Publishing)
        SimpleTCP = Simple\\sTCP/IP\\sServices
        IISWebserver = Internet\\sInformation\\sServices
        IISHostableWebCore = Internet\\sInformation\\sServices\\sHostable\\sWeb\\sCore
'@
}
