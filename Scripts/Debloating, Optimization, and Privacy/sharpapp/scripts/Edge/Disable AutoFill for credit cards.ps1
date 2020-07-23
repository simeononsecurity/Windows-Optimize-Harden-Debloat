### Disable AutoFill for credit cards ###
### Microsoft Edge's AutoFill feature lets users auto complete credit card information in web forms using previously stored information. ### 
### If you enable this policy, Autofill never suggests or fills credit card information, nor will it save additional credit card information that users might submit while browsing the web.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Edge")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\Edge" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Edge" -Name "AutofillCreditCardEnabled" -Type DWord -Value 0 -Force
