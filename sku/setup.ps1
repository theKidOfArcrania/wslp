#Requires -Version 7.0

Param (
  [Parameter(mandatory=$true)]
  [string] $InstallImage,
  [switch] $BuildWSL = $false,
  [Parameter(mandatory=$true)]
  [string] $Output
)

$ErrorActionPreference = "Stop"

$WSLPath = "$PSScriptRoot\..\wsl"
try {
  $x = Get-Item "$WSLPath\build.sh"
} catch {
  Write-Error "Please run setup.ps1 in the build tree of this codebase"
  exit 1
}

if $BuildWSL {
  Write-Host "[*] Building WSL container..."
  try {
    if (((wsl -e uname) -Ne "Linux") {
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

Write-Host "[*] Checking WSL build artifacts..."
$WSLFiles = @(
  "$WSLPath\containerd\containerd",
  "$WSLPath\disk.img",
  "$WSLPath\run_shared.sh"
)
$Unattend = "$PSScriptRoot\ctf_unattended.xml"

$WSLFiles |% { Get-Item $_ }
Get-Item $Unattend

Write-Host "[*] Creating installation media to $Output..."
$sz = [uint64](($disk.Size + 10MB) / 1MB) * 1MB
New-VHD -Path $Output -SizeBytes $sz

$disk_out = Mount-DiskImage -Passthru $Output
try {
  $letter_out = ((Get-Disk $disk_out.Number | Get-Partition).DriveLetter |? { $_ })

  $disk = Mount-DiskImage -Passthru -Access ReadOnly $InstallImage
  try {
    if ($disk.StorageType -Eq 1) {
      $letter = ((Get-Volume -DiskImage $disk).DriveLetter |? { $_ })
    } else if ($disk.StorageType -Eq 2 -Or $disk.StorageType -Eq 3) {
      $letter = ((Get-Disk $disk.Number | Get-Partition).DriveLetter |? { $_ })
    } else {
      Write-Error "Not a valid storage type"
      exit 1
    }
    Copy-Item -Recurse "$letter:/*" "$letter_out:/"
  } finally {
    $disk | Dismount-DiskImage
  }

  Write-Host "[*] Copying OEM files"
  $OEMBase = "$letter_out:\sources\`$`$OEM`$`$\`$1"
  New-Item -ItemType d "$OEMBase\Windows\Panther"
  New-Item -ItemType d "$OEMBase\OEM"
  Copy-Item $Unattend "$OEMBase\Windows\Panther\"
  $WSLFiles |% { Copy-Item $_ "$OEMBase\OEM" }
  Write-Host "[*] Installation media created at: $Output"
} finally {
  $disk_out | Dismount-DiskImage
}

