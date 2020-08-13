mkdir C:\temp\Branding
if (test-path C:\temp\branding){
Write-host branding files already moved
}else {
copy-item -Path .\Files\Branding\* -Destination C:\temp\Branding\ -Recurse -Force
}
copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Screen\lockscreen.jpg -Force
copy-item -Path .\Files\Branding\wallpaper.jpg -Destination C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg -Force
copy-item -Path .\Files\Branding\oemlogo.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
copy-item -Path .\Files\Branding\user*.png -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
copy-item -Path .\Files\Branding\user*.bmp -Destination "C:\ProgramData\Microsoft\User Account Pictures" -Force
reg add "HKEY_CURRENT_USER\Control Panel\Desktop" /v Wallpaper /t REG_SZ /d C:\Windows\Web\Wallpaper\Theme1\wallpaper.jpg /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\OEMInformation" /v Logo /t REG_SZ /d "C:\ProgramData\Microsoft\User Account Pictures\oemlogo.bmp" /f