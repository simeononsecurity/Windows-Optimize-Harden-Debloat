### Disable Bing in Windows Search ### 
### Like Google, Bing is a search engine that needs your data to improve its search results. Windows 10, by default, sends everything you search for in the Start Menu to their servers to give you results from Bing search. ###
### These searches are then uploaded to Microsoft's Privacy Dashboard.
New-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "BingSearchEnabled" -Type DWord -Value 0 -Force