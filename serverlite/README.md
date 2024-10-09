# wslp-serverlite

This is a trimmed down version of the server code that is going to run, just to
show how the multiplex connections work.

You must first build the wslp-sku component, which should provide a .vhdx
artifact which you should then run in a separate VM. You can run this code to
set up a V-switch that you can then attach to the challenge VM (in fact this is
what is run on the actual server):

```ps1
$ErrorActionPreference = "Stop"
$switchName = "HostOnly"
$dhcpName = "DHCP-$switchName"
Write-Host "#[info] Creating vswitch"
if (-Not (Get-VMSwitch |? { $_.Name -Eq $switchName })) {
    New-VMSwitch -Name $switchName -SwitchType Internal
    #New-NetNat -Name $switchName -InternalIPInterfaceAddressPrefix "10.69.0.0/16"
}

Write-Host "#[info] Assigning IP Address for switch"
$ifIndex = (Get-NetAdapter |? { $_.Name -Like "*$switchName*" })[0].ifIndex
if (-Not (Get-NetIpAddress -InterfaceIndex 6 |? { $_.IPAddress -Eq "10.69.0.1"})) {
    New-NetIpAddress -IPAddress 10.69.0.1 -InterfaceIndex $ifIndex -PrefixLength 16
}

Write-Host "#[info] Configuring DHCP Server"
if (-Not (Get-DhcpServerV4Scope |? { $_.Name -Eq $dhcpName })) {
    Add-DhcpServerV4Scope -Name $dhcpName `
        -StartRange 10.69.0.50 `
        -EndRange 10.69.255.254 `
        -SubnetMask 255.255.0.0
}

Set-DhcpServerV4OptionValue -Router 10.69.0.1 -DnsServer 8.8.8.8
```

You will need have installed Hyper-V and DHCP features (optionally). The DHCP
feature may only be allowed on window server SKUs.
