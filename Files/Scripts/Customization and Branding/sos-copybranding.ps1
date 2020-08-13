if (test-path C:\temp\branding){
Write-host branding files already moved
}else {
mkdir C:\temp\Branding
copy-item -Path .\Files\Branding\* -Destination C:\temp\Branding\ -Recurse -Force
}
copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Screen\lockscreen.jpg -Force
copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg -Force
copy-item -Path .\Files\Branding\oemlogo.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
copy-item -Path .\Files\Branding\user*.png -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
copy-item -Path .\Files\Branding\user*.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
Set-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name Wallpaper -Type String -Value C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg -Force
Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" -Name Logo -Type String -Value "C:\ProgramData\Microsoft\User Account Pictures\oemlogo.bmp" -Force