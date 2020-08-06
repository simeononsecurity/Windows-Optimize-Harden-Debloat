#https://gist.github.com/MyITGuy/9628895
#http://stu.cbu.edu/java/docs/technotes/guides/deploy/properties.html

#<Windows Directory>\Sun\Java\Deployment\deployment.config
#- or -
#<JRE Installation Directory>\lib\deployment.config

Write-Output "Installing Java Configurations - Please Wait."
Write-Output "Window will close after install is complete"

If (Test-Path -Path "C:\Windows\Sun\Java\Deployment\"){
    Write-Host "Configs Already Deployed"
}Else {
    Mkdir "C:\Windows\Sun\Java\Deployment\"
    Mkdir "C:\temp\JAVA"
    Copy-Item -Path .\Files\deployment.config -Destination "C:\Windows\Sun\Java\Deployment\" -Force
    Copy-Item -Path .\Files\deployment.properties -Destination "C:\temp\JAVA\" -Force
    Copy-Item -Path .\Files\exception.sites -Destination "C:\temp\JAVA\"" -Force
}
