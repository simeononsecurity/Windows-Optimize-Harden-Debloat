# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License.
using module .\..\..\Common\Common.psm1
using module .\..\SslSettingsRule.psm1
# Header
<#
    .SYNOPSIS
        Convert the contents of an xccdf check-content element into a
        WebConfigurationPropertyRule object
    .DESCRIPTION
        The WebConfigurationPropertyRule class is used to extract the web
        configuration settings from the check-content of the xccdf. Once a STIG
        rule is identified as a web configuration property rule, it is passed
        to the WebConfigurationPropertyRule class for parsing and validation.
#>
class SslSettingsRuleConvert : SslSettingsRule
{
    <#
        .SYNOPSIS
            Empty constructor for SplitFactory
    #>
    SslSettingsRuleConvert ()
    {
    }

    <#
        .SYNOPSIS
            Converts a xccdf STIG rule element into a Web Configuration Property Rule
        .PARAMETER XccdfRule
            The STIG rule to convert
    #>
    SslSettingsRuleConvert ([xml.xmlelement] $XccdfRule) : base ($XccdfRule, $true)
    {
        $this.SetSslValue()

        if ($this.conversionstatus -eq 'pass')
        {
            $this.SetDuplicateRule()
        }
        $this.SetDscResource()
    }

    #region Methods
    <#
        .SYNOPSIS
            Extracts the value from the check-content and sets the value
        .DESCRIPTION
            Gets the value from the xccdf content based on known matches and
            sets the value accordingly
    #>
    [void] SetSslValue ()
    {
        $thisValue = [string]
        switch ($this.rawstring)
        {
            {$PSItem -match 'Verify the "Clients Certificate Required"'}
            {
                $thisValue = 'SslRequireCert'
                break
            }
            {($PSItem -match 'Client Certificates Required') -and ($PSItem -match 'set to "ssl128"') -and ($PSItem -match 'If the "Require SSL"')}
            {
                $thisValue = 'Ssl,SslNegotiateCert,SslRequireCert,Ssl128'
                break
            }
            {$PSItem -match 'If the "Require SSL"'}
            {
                $thisValue = 'Ssl'
            }
        }

        if ($null -ne $thisValue)
        {
            Write-Verbose -Message $("[$($MyInvocation.MyCommand.Name)] Found value: {0}"  -f $thisValue)

            if (-not $this.SetStatus($thisValue))
            {
                $this.set_Value($thisValue)
            }
        }
        else
        {
            Write-Verbose -Message "[$($MyInvocation.MyCommand.Name)] No Key or Value found"
        }
    }

    hidden [void] SetDscResource ()
    {
        if ($null -eq $this.DuplicateOf)
        {
            $this.DscResource = 'xSslSettings'
        }
        else
        {
            $this.DscResource = 'None'
        }
    }

    static [bool] Match ([string] $CheckContent)
    {
        if ($CheckContent -Match 'SSL Settings')
        {
            return $true
        }

        return $false
    }

    #endregion
}
