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

RUN iwr -useb 'https://simeononsecurity.ch/scripts/windowsoptimizeandharden.ps1'|iex

ENTRYPOINT ENTRYPOINT [ "powershell.exe" ]
