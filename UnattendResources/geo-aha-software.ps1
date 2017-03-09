# Cygwin
Start-Process C:\Windows\System32\msiexec.exe -ArgumentList "/i \\sc12-dp.klient.uib.no\sc12-src\Cygwin\1.7.24\Cygwin1.7.24.msi /qb" -Wait

# MikTex
#Unblock-File -Path \\sc12-dp.klient.uib.no\SC12-SRC\MikTex\2.9\2016.10\miktexsetup.exe -Verbose
#Start-Process \\sc12-dp.klient.uib.no\SC12-SRC\MikTEX\2.9\2016.10\miktexsetup.exe -ArgumentList " --quiet --local-package-repository=\\sc12-dp.klient.uib.no\SC12-SRC\MikTEX\2.9\2016.10 --shared --use-registry=no --package-set=complete install" -Wait -NoNewWindow -Verbose

# Firefox
Unblock-File -Path "\\sc12-dp.klient.uib.no\SC12-SRC\Mozilla\Firefox\x64\51\.0.1\Firefox Setup 51.0.1.exe" -Verbose
Start-Process "\\sc12-dp.klient.uib.no\SC12-SRC\Mozilla\Firefox\x64\51\.0.1\Firefox Setup 51.0.1.exe" -ArgumentList ' -ms' -Wait -NoNewWindow

# Java JRE
#Unblock-File -Path "\\sc12-dp.klient.uib.no\SC12-SRC\Java\JRE8\u121\x64\install.cmd" -Verbose
Start-Process "\\sc12-dp.klient.uib.no\SC12-SRC\Java\JRE8\u121\x64\install.cmd" -Wait -NoNewWindow
