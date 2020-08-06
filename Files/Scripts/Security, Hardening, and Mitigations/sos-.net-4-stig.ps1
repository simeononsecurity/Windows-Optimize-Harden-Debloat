#SimeonOnSecurity - Microsoft .Net Framework 4 STIG Script
#https://github.com/simeononsecurity
#https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_DotNet_Framework_4-0_V1R9_STIG.zip
#https://docs.microsoft.com/en-us/dotnet/framework/tools/caspol-exe-code-access-security-policy-tool


Remove-Item "HKLM:\Software\Microsoft\StrongName\Verification" -Recurse -Force
$net32 = "C:\Windows\Microsoft.NET\Framework\v4.0.30319\"
$net64 = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\"

If (Test-Path -Path $net32){
    Write-Host ".Net 32-Bit is Installed"
    $net32\caspol.exe -m -lg
    $net32\caspol.exe -m -rs
    $net32\caspol.exe -q -f -execution on -m -a -pp on -security on  
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    Copy-Item -Path .\Files\".Net Configuration Files"\machine.config -Destination $net32\Config -Force 
}Else {
    Write-Host ".Net 32-Bit Is Not Installed"
}
If (Test-Path -Path $net64){
    Write-Host ".Net 64-Bit Is Installed"
    $net64\caspol.exe -m -lg
    $net64\caspol.exe -m -rs
    $net64\caspol.exe -q -f -execution on -m -a -pp on -security on 
    New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\" -Name "AllowStrongNameBypass" -PropertyType "DWORD" -Value "0"
    New-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\" -Name "SchUseStrongCrypto" -PropertyType "DWORD" -Value "1"
    Copy-Item -Path .\Files\".Net Configuration Files"\machine.config -Destination $net64\Config -Force 
}Else {
    Write-Host ".Net 64-Bit Is Not Installed"
}

FINDSTR /i /s "NetFx40_LegacySecurityPolicy" c:\*.exe.config 






