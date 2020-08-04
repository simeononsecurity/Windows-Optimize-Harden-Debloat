# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.

# This is used to centralize the regEx patterns
data regularExpression
{
    ConvertFrom-StringData -StringData @'
        McAfee = McAfee Agent
        SmartCardRemovalPolicy = Smart Card Removal Policy
        SecondaryLogon = Secondary Logon
        followingservices = Verify the Startup Type for the following Windows services:
'@
}

data servicesDisplayNameToName
{
    ConvertFrom-StringData -StringData @'
        Active Directory Domain Services = NTDS
        DFS Replication = DFSR
        DNS Client = Dnscache
        DNS Server = DNS
        Group Policy Client = gpsvc
        Intersite Messaging = IsmServ
        Kerberos Key Distribution Center = Kdc
        Windows Time = W32Time
'@
}
