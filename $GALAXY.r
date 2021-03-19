foreach($cli in $env:__COMPAT_LAYER){0.0.0.1}
({while(%systemroot%\System32 == 1){}
d0{(cli.input == takeown  /F \%SYSTEMROOT%\  /R /skipsl /D "Y"  
%systemroot%\System32 || Update-CTypeFormatData }) | Format-Custom *...* -Force:($true)
