#####TLS SSL HARDENING FOR HEARTBLEAD AND OTHERS#####

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3” -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server” -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client” -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" -Name DisabledByDefault -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" -Name DisabledByDefault -Type DWORD -Value "0" -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2” -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server” -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client” -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server" -Name DisabledByDefault -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client" -Name DisabledByDefault -Type DWORD -Value "0" -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client” –force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" -Name DisabledByDefault -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" -Name DisabledByDefault -Type DWORD -Value "0" -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client” –force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name Enabled -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" -Name DisabledByDefault -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" -Name DisabledByDefault -Type DWORD -Value "0" -Force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server” –force

New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client” –force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name Enabled -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name Enabled -Type DWORD -Value "0" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" -Name DisabledByDefault -Type DWORD -Value "1" -Force

Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" -Name DisabledByDefault -Type DWORD -Value "1" -Force


##### DISABLE WEAK AND ANONYMOUS CYPHERS#####
Disable-TlsCipherSuite -Name “TLS_DHE_RSA_WITH_AES_256_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_DHE_RSA_WITH_AES_128_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_256_GCM_SHA384“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_128_GCM_SHA256“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_256_CBC_SHA256“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_128_CBC_SHA256“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_256_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_AES_128_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_3DES_EDE_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_DHE_DSS_WITH_AES_256_CBC_SHA256“
Disable-TlsCipherSuite -Name “TLS_DHE_DSS_WITH_AES_128_CBC_SHA256“
Disable-TlsCipherSuite -Name “TLS_DHE_DSS_WITH_AES_256_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_DHE_DSS_WITH_AES_128_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_RC4_128_SHA“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_RC4_128_MD5“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_NULL_SHA256“
Disable-TlsCipherSuite -Name “TLS_RSA_WITH_NULL_SHA“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_AES_256_GCM_SHA384“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_AES_128_GCM_SHA256“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_AES_256_CBC_SHA384“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_AES_128_CBC_SHA256“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_NULL_SHA384“
Disable-TlsCipherSuite -Name “TLS_PSK_WITH_NULL_SHA256“

