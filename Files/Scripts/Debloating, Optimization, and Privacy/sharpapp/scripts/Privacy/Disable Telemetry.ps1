### Disable telemetry in Windows 10 ###
### As you use Windows 10, Microsoft will collect usage information. All its options are available in Settings -> Privacy - Feedback and Diagnostics. There you can set the options "Diagnostic and usage data" to Basic, Enhanced and Full. This will set diagnostic data to Basic, which is the lowest level available for all consumer versions of Windows 10 ###
### NOTE: Diagnostic Data must be set to Full to get preview builds from Windows-Insider-Program! Just set the value of the AllowTelemetry key to "3" to revert the policy changes. All other changes remain unaffected.
New-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\" -Name "DataCollection" -Type DWord -Value 0 -Force
# Stop and Disable Diagnostic Tracking Service
New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\DiagTrack" -Name "Start" -Type DWord -Value 4 -Force
Stop-Service -Name DiagTrack
Set-Service -Name DiagTrack -StartupType Disabled
# Stop and Disable dmwappushservice Service
New-ItemProperty -Path "HKLM:\SYSTEM\ControlSet001\Services\dmwappushsvc" -Name "Start" -Type DWord -Value 4 -Force
Stop-Service -Name dmwappushservice
Set-Service -Name dmwappushservice -StartupType Disabled