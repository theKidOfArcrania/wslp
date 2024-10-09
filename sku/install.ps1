$ErrorActionPreference = "Stop"
try {
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Microsoft-Windows-Subsystem-Linux -All
        exit 2 # reboot and restart this command
    }
    wsl --update --inbox
} catch {
    exit 3
}
