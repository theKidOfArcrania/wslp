icacls C:\OEM\flag2.2.txt /setowner SYSTEM
icacls C:\OEM\flag2.2.txt /inheritance:r
wsl --install Debian -n
debian install --root
debian run /mnt/c/OEM/install.sh
debian config --default-user ctf

$action = New-ScheduledTaskAction -Execute (where.exe debian) -Argument "run bash -c /home/ctf/runner update"
$principal = New-ScheduledTaskPrincipal -RunLevel Highest
$trigger = New-ScheduledTaskTrigger `
  -Once `
  -At (Get-Date) `
  -RepetitionInterval (New-TimeSpan -Minutes 1) `
  -RepetitionDuration ([System.TimeSpan]::MaxValue)
Register-ScheduledTask -Trigger $trigger -Action $action -Principal $principal -TaskName "update_wsl"
