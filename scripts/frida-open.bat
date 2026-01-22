@echo off
start "Frida Server" cmd /k "adb shell su root /data/local/tmp/frida &"
timeout /t 2
start "Process List" cmd /k "frida-ps -Uai"