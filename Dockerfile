FROM mcr.microsoft.com/windows/server:ltsc2022-amd64

LABEL org.opencontainers.image.source="https://github.com/simeononsecurity/windows-optimize-harden-debloat"
LABEL org.opencontainers.image.description="Test Image for SimeonOnSecurity"
LABEL org.opencontainers.image.authors="simeononsecurity"
LABEL BaseImage="windows/server:ltsc2022-amd64"
LABEL RunnerVersion=${RUNNER_VERSION}

ARG RUNNER_VERSION
ENV container docker
ENV chocolateyUseWindowsCompression false
SHELL ["powershell.exe"]

RUN iex ((new-object net.webclient).DownloadString('https://chocolatey.org/install.ps1')); \
    choco feature disable --name showDownloadProgress

RUN refreshenv

RUN Start-Job -Name "Installing Windows Updates" -ScriptBlock { Write-Host "Install Latest Windows Updates" ; choco install pswindowsupdate ; Set-Executionpolicy -ExecutionPolicy RemoteSigned -Force ; Import-Module PSWindowsUpdate -Force ; Add-WUServiceManager -ServiceID 7971f918-a847-4430-9279-4a52d1efe18d -Confirm:$false ; Install-WindowsUpdate -MicrosoftUpdate -AcceptAll -Install ; Get-WuInstall -AcceptAll -IgnoreReboot -IgnoreUserInput -nottitle 'preview' ; Get-WindowsUpdate –Install }    

RUN iwr -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'|iex

ENTRYPOINT ENTRYPOINT [ "powershell.exe" ]
