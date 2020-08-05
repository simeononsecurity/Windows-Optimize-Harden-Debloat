#https://www.itsupportguides.com/knowledge-base/tech-tips-tricks/how-to-customise-firefox-installs-using-mozilla-cfg/]
$firefox64 = "C:\Program Files\Mozilla Firefox"
$firefox32 = "C:\Program Files (x86)\Mozilla Firefox"
echo "Installing Firefox Configurations - Please Wait."
echo "Window will close after install is complete"
If (Test-Path -Path $firefox64){
    Copy-Item -Path ".\Files\FireFox Configuration Files\defaults" -Destination $firefox64 -Force -Recurse
    Copy-Item -Path ".\Files\FireFox Configuration Files\mozilla.cfg" -Destination $firefox64 -Force
    Copy-Item -Path ".\Files\FireFox Configuration Files\local-settings.js" -Destination $firefox64 -Force 
    Write-Host "Firefox 64-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 64-Bit Is Not Installed"
}
If (Test-Path -Path $firefox32){
    Copy-Item -Path ".\Files\FireFox Configuration Files\defaults" -Destination $firefox32 -Force -Recurse
    Copy-Item -Path ".\Files\FireFox Configuration Files\mozilla.cfg" -Destination $firefox32 -Force
    Copy-Item -Path ".\Files\FireFox Configuration Files\local-settings.js" -Destination $firefox32 -Force 
    Write-Host "Firefox 32-Bit Configurations Installed"
}Else {
    Write-Host "FireFox 32-Bit Is Not Installed"
}
