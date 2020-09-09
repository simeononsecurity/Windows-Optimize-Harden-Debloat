$GPOLIST = Get-ChildItem *.pol -recurse
foreach ($item in $GPOLIST){
    .\Files\LGPO\LGPO.exe /parse /m $item | add-content .\computer.txt
    .\Files\LGPO\LGPO.exe /parse /u $item | add-content .\user.txt
}