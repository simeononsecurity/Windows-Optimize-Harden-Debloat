### Open privacy settings
$Result = [System.Windows.Forms.MessageBox]::Show("Would you like to open the Settings > Privcay page?","SharpApp",4)
If ($Result -eq "Yes")
{
    Start-Process "ms-settings:privacy-general"
}
