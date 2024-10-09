$ErrorActionPreference = "Stop"
try {
    $enabled = $false
    if ((Get-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName Microsoft-Windows-Subsystem-Linux -All
        $enabled = $true
    }
    if ((Get-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName HypervisorPlatform -All
        $enabled = $true
    }
    if ((Get-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform).State -Ne 'Enabled') {
        Enable-WindowsOptionalFeature -Online -NoRestart -FeatureName VirtualMachinePlatform -All
        $enabled = $true
    }
    if ($enabled) {
        exit 2 # reboot and restart this command
    }

    exit 0
} catch {
    exit 3
}
