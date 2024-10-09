icacls C:\OEM\flag2.2.txt /setowner SYSTEM
icacls C:\OEM\flag2.2.txt /inheritance:r
wsl --install Debian -n
debian install --root
debian run /mnt/c/OEM/install.sh
debian config --default-user ctf

$action = New-ScheduledTaskAction -Execute (where.exe debian) -Argument "run /home/ctf/runner update"
$principal = New-ScheduledTaskPrincipal -UserId ctf -RunLevel Highest
$trigger = New-ScheduledTaskTrigger `
  -Once `
  -At (Get-Date) `
  -RepetitionInterval (New-TimeSpan -Minutes 1) `
  -RepetitionDuration (New-TImeSpan -Days 50)
Register-ScheduledTask -Trigger $trigger -Action $action -Principal $principal -TaskName "update_wsl"
