@echo off
make
echo completado
"C:\devkitPro\tools\bin\nxlink.exe" --address 192.168.1.129 incognito.nro
%systemroot%\system32\timeout.exe 55
exit
