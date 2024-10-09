#Requires -Version 7.0

Param (
  [switch] $BuildWSL = $false,
  [string] $BaseInstall = $null,
  [Parameter(mandatory=$true)]
  [string] $InstallVHDX,
  [Parameter(mandatory=$true)]
  [string] $OutputVHDX,
  [string] $Password = "password",
  [string] $SwitchName = "Default Switch"
)

function Remove-IfExists() {
  Param(
    [Parameter(mandatory=$true)]
    $Path
  )
  $ErrorActionPreference = "Stop"

  $exists = $false
  try {
    $x = Get-Item $Path
    $exists = $true
  } catch { }

  if ($exists) {
    Remove-Item $Path
  }
}

$ErrorActionPreference = "Stop"

$WSLPath = "$PSScriptRoot\..\wsl"

if ($BaseInstall -Ne $null -And $BaseInstall -Ne "") {
  if ($BuildWSL) {
    try {
      $x = Get-Item "$WSLPath\build.sh"
    } catch {
      Write-Error "Please run setup.ps1 in the build tree of this codebase"
      exit 1
    }

    Write-Host "[*] Building WSL container..."
    try {
      if ((wsl -e uname) -Ne "Linux") {
        Write-Error "err"
      }
    } catch {
      Write-Error "This requires WSL to be installed"
      exit 1
    }

    wsl --cd "$WSLPath" -e bash -c "./build.sh"
    if (-Not $?) {
      Write-Error "Failed to build linux code"
    }
  }

  Write-Host "[*] Checking files..."
  $OEMFiles = @(
    "$WSLPath\containerd\containerd",
    "$WSLPath\disk.img",
    "$WSLPath\runner\runner",
    "$PSScriptRoot\install.sh",
    "$PSScriptRoot\install.ps1",
    "$PSScriptRoot\..\flag1.txt",
    "$PSScriptRoot\..\flag2.1.txt",
    "$PSScriptRoot\..\flag2.2.txt"
  )
  $Unattend = "$PSScriptRoot\unattend.xml"
  $EFIRoot = "$PSScriptRoot\efi"

  $OEMFiles |% { $x = Get-Item $_ }
  $x = Get-Item $Unattend
  $x = Get-Item $EFIRoot

  Write-Host "[*] Creating installation media to $InstallVHDX..."
  $sz = [uint64]((Get-Item $BaseInstall).Length * 1.3 / 1MB) * 1MB
  Remove-IfExists $InstallVHDX
  $x = New-VHD -Path $InstallVHDX -SizeBytes $sz -Fixed
  $diskimg_out = Mount-DiskImage -PassThru $InstallVHDX
  $disk_out = $diskimg_out | Initialize-Disk -PassThru

  try {
    Write-Host "[*] Setting up boot partition..."
    $x = $disk_out | New-Partition -AssignDriveLetter -Size 10MB |
      Format-Volume -FileSystem FAT -Confirm:$false -Force
    $boot_part = (($disk_out | Get-Partition) |? { $_.DriveLetter })[0]
    $letter_out = ($boot_part.DriveLetter)

    $x = Copy-Item -Recurse "$EFIRoot\*" "${letter_out}:\"
    $x = $boot_part | Set-Partition -IsHidden $true

    Write-Host "[*] Setting up main partition..."
    $x = $disk_out | New-Partition -AssignDriveLetter -UseMaximumSize |
      Format-Volume -FileSystem NTFS -Confirm:$false -Force
    $letter_out = (($disk_out | Get-Partition).DriveLetter |? { $_ })

    $disk = Mount-DiskImage -Passthru -Access ReadOnly $BaseInstall
    try {
      if ($disk.StorageType -Eq 1) {
        $letter = ((Get-Volume -DiskImage $disk).DriveLetter |? { $_ })
      } elseif ($disk.StorageType -Eq 2 -Or $disk.StorageType -Eq 3) {
        $letter = ((Get-Disk $disk.Number | Get-Partition).DriveLetter |? { $_ })
      } else {
        Write-Error "Not a valid storage type"
        exit 1
      }
      Write-Host "[*] Copying base files"
      $x = Copy-Item -Recurse "${letter}:\*" "${letter_out}:\"
    } finally {
      $disk | Dismount-DiskImage | Out-Null
    }

    Write-Host "[*] Copying OEM files"
    $OEMBase = "${letter_out}:\sources\`$OEM`$\`$1"
    $x = New-Item -ItemType d "$OEMBase\Windows\Panther"
    $x = New-Item -ItemType d "$OEMBase\OEM"
    $x = (Get-Content -Raw $Unattend) -replace 'REPLACE_ME', "$Password" |
      Set-Content -NoNewLine "$OEMBase\Windows\Panther\"
    $OEMFiles |% { Copy-Item $_ "$OEMBase\OEM" }
    Write-Host "[*] Installation media created at: $InstallVHDX"
  } finally {
    $diskimg_out | Dismount-DiskImage | Out-Null
  }
}

try {
  $x = Get-Item $InstallVHDX
} catch {
  Write-Error "Please specify -BaseInstall to build the install VHDX file"
}

Write-Host "[*] Creating output VHDX"
Remove-IfExists $OutputVHDX
$x = New-VHD -Path $OutputVHDX -SizeBytes 20GB -Fixed

Write-Host "[*] Configuring windows_setup VM to run windows setup"
$vm = New-VM -Name "windows_setup" -MemoryStartupBytes 4GB -Generation 2 `
  -BootDevice VHD -VHDPath $InstallVHDX
Set-VM -VM $vm -CheckpointType Disabled -AutomaticStartAction Nothing `
  -AutomaticStopAction TurnOff -AutomaticCheckpointsEnabled $false
Set-VMFirmware -VM $vm -EnableSecureBoot Off
Set-VMProcessor -VM $vm -Count 2 -ExposeVirtualizationExtensions $true
Add-VMHardDiskDrive -VM $vm -ControllerType SCSI -Path $OutputVHDX
Add-VMNetworkAdapter -VM $vm -SwitchName $SwitchName
Set-VMKeyProtector -VM $vm -NewLocalKeyProtector
Enable-VMTPM -VM $vm
Start-VM $vm
Write-Host "[*] Setting up image... You may need to click through the windows setup"
