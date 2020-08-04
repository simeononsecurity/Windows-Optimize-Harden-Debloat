choco install accesschk -y
Import-Module .\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\Invoke-HardeningKitty.ps1
Invoke-HardeningKitty -EmojiSupport -Log $true -Report $true -Mode HailMary -FileFindingList .\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\lists\finding_list_0x6d69636b_machine.csv -BinaryAccesschk "C:\ProgramData\chocolatey\lib\accesschk\tools\accesschk64.exe" 
Invoke-HardeningKitty -EmojiSupport -Log $true -Report $true -Mode HailMary -FileFindingList .\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\lists\finding_list_0x6d69636b_user.csv -BinaryAccesschk "C:\ProgramData\chocolatey\lib\accesschk\tools\accesschk64.exe" 
Invoke-HardeningKitty -EmojiSupport -Log $true -Report $true -Mode HailMary -FileFindingList .\Scripts\"Security, Hardening, and Mitigations"\HardeningKitty\lists\finding_list_msft_edge_machine.csv -BinaryAccesschk "C:\ProgramData\chocolatey\lib\accesschk\tools\accesschk64.exe" 
