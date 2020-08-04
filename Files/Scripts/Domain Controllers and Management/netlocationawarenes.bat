@echo off
REM 01/21/2019
 
REM Restart the NLA service to force re-detecting that computer is on a domain. 
REM Unlike restarting the network adapter, this does not completely disconnect from network.
REM Can run this from a Scheduled Task at Startup.  Run as SYSTEM, 1 minute delay, only run 
REM if "Any Connection" available.
 
REM %0 is the name of the batch file. 
REM ~dp gives you the drive and path of the specified argument, with trailing \.
set ScriptPath=%~dp0
REM ~nx gives you the filename and extension only.
set ScriptName=%~nx0
 
REM Clever approach to redirect stdout and stderr for a group of commands
REM See http://stackoverflow.com/a/13400446/550712:
> "%ScriptPath%\RestartNLAService.log" 2>&1 (
    echo ========================
    echo Current firewall profile
    echo ========================
    netsh advfirewall monitor show currentprofile
    echo =======================
    echo Restart the NLA service 
    echo =======================
    echo Stop the Network Connected Devices, Network List, and Network Location Awareness services
    net stop ncdautosetup
    net stop netprofm
    net stop nlasvc
    echo Start the NLA service
    net start nlasvc
    echo Network Connected Devices and Network List services are Manual start, so will be started if needed
    echo.
    echo ========================
    echo Updated firewall profile
    echo ========================
    netsh advfirewall monitor show currentprofile
)
type "%ScriptPath%\RestartNLAService.log"
 
REM Do not put a PAUSE here, since this will run from a scheduled task