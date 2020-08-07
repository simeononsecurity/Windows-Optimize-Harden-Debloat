#https://gist.github.com/MyITGuy/9628895
#http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

#<Windows Directory>\Sun\Java\Deployment\deployment.config
#- or -
#<JRE Installation Directory>\lib\deployment.config

If (Test-Path -Path "C:\Windows\Sun\Java\Deployment\deployment.config"){
    Write-Host "Deployment Config Already Installed"
}Else {
    Write-Output "Installing Java Deployment Config...."
    Mkdir "C:\Windows\Sun\Java\Deployment\"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
    Write-Output "JAVA Configs Installed"
}
If (Test-Path -Path "C:\temp\JAVA\"){
    Write-Host "Configs Already Deployed"
}Else {
    Write-Output "Installing Java Configurations...."
    Mkdir "C:\temp\JAVA"
    Copy-Item -Path .\Files\"JAVA Configuration Files"\deployment.properties -Destination "C:\temp\JAVA\" -Force
    Copy-Item -Path .\Files\"JAVA Configuration Files"\exception.sites -Destination "C:\temp\JAVA\" -Force
    Write-Output "JAVA Configs Installed"
}
