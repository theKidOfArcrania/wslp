$ErrorActionPreference = "Stop"
try {
    $enabled = $true
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Microsoft-Windows-Subsystem-Linux -All
        $enabled = $true
    }
    if ((Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName HypervisorPlatform -All
        $enabled = $true
    }
    if ($enabled) {
        exit 2 # reboot and restart this command
    }

    icacls C:\OEM\flag2.2.txt /setowner SYSTEM
    icacls C:\OEM\flag2.2.txt /inheritance:r

    wsl --install Debian -n
    debian install --root
    debian run /mnt/c/OEM/install.sh
    debian config --default-user ctf
    exit 0
} catch {
    exit 3
}
