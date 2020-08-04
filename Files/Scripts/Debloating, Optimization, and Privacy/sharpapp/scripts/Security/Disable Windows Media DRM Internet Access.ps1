### Disable Windows Media DRM Internet Access ###
### DRM stands for digital rights management. DRM is a technology used by content providers, such as online stores, to control how the digital music and video files you obtain from them are used and distributed. Online stores sell and rent songs and movies that have DRM applied to them. ###
### If the Windows Media Digital Rights Management should not get access to the Internet, you can enable this policy to prevent it.
If (!(Test-Path "HKLM:\Software\Policies\Microsoft\WMDRM")) {
	New-Item -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Force | Out-Null
}
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\WMDRM" -Name "DisableOnline" -Type DWord -Value 1 -Force
