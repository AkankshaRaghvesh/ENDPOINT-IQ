# Step 2: Windows Endpoint Health Collector

$collectedAt = (Get-Date).ToString("o")

# Device Identity
$deviceName = $env:COMPUTERNAME
$username = $env:USERNAME

$serialNumber = (Get-CimInstance Win32_BIOS).SerialNumber

# OS Information
$osInfo = Get-CimInstance Win32_OperatingSystem
$osCaption = $osInfo.Caption
$osVersion = $osInfo.Version
$osBuild = $osInfo.BuildNumber
$lastBootTime = $osInfo.LastBootUpTime

# Patch Information
$lastUpdate = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
$lastUpdateDate = $lastUpdate.InstalledOn

# Pending Reboot Check
$pendingReboot = $false
$rebootKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
)

foreach ($key in $rebootKeys) {
    if (Test-Path $key) {
        $pendingReboot = $true
    }
}

# Defender Status
$defenderStatus = "Unknown"
try {
    $mpStatus = Get-MpComputerStatus
    $defenderStatus = if ($mpStatus.RealTimeProtectionEnabled) { "On" } else { "Off" }
} catch {
    $defenderStatus = "Unavailable"
}

# BitLocker Status
$bitlockerEnabled = $false
try {
    $blv = Get-BitLockerVolume -MountPoint "C:"
    if ($blv.ProtectionStatus -eq 1) {
        $bitlockerEnabled = $true
    }
} catch {
    $bitlockerEnabled = $false
}

# Disk Health
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='C:'"
$freePercent = [math]::Round(($disk.FreeSpace / $disk.Size) * 100, 2)

# Build Output Object
$endpointHealth = [PSCustomObject]@{
    collected_at                   = $collectedAt
    device_name                    = $deviceName
    username                       = $username
    serial_number                  = $serialNumber
    os_caption                     = $osCaption
    os_version                     = $osVersion
    os_build                       = $osBuild
    last_boot_time                 = $lastBootTime
    last_update_installed_date     = $lastUpdateDate
    pending_reboot                 = $pendingReboot
    defender_realtime_protection   = $defenderStatus
    bitlocker_enabled              = $bitlockerEnabled
    system_drive_free_percent      = $freePercent
}
# --- Password Policy (local) ---
try {
    $pwdPol = net accounts
    $minLen = ($pwdPol | Select-String "Minimum password length").ToString().Split(":")[1].Trim()
    $maxAge = ($pwdPol | Select-String "Maximum password age").ToString().Split(":")[1].Trim()
} catch {
    $minLen = "Unknown"
    $maxAge = "Unknown"
}

# --- Antivirus Signature Age (Microsoft Defender) ---
try {
    $mp = Get-MpComputerStatus
    $sigDate = $mp.AntivirusSignatureLastUpdated
    $sigAgeDays = (New-TimeSpan -Start $sigDate -End (Get-Date)).Days
} catch {
    $sigDate = $null
    $sigAgeDays = $null
}

# Add these into your JSON object/hashtable
$endpointHealth | Add-Member -NotePropertyName "password_min_length" -NotePropertyValue $minLen -Force
$endpointHealth | Add-Member -NotePropertyName "password_max_age" -NotePropertyValue $maxAge -Force
$endpointHealth | Add-Member -NotePropertyName "av_signature_last_updated" -NotePropertyValue $sigDate -Force
$endpointHealth | Add-Member -NotePropertyName "av_signature_age_days" -NotePropertyValue $sigAgeDays -Force

# --- Battery Health & Cycle Count ---
try {
    $battery = Get-WmiObject -Namespace root\wmi -Class BatteryFullChargedCapacity
    $design = Get-WmiObject -Namespace root\wmi -Class BatteryStaticData
    $status = Get-WmiObject -Class Win32_Battery

    if ($battery -and $design) {
        $healthPercent = [math]::Round(
            ($battery.FullChargedCapacity / $design.DesignedCapacity) * 100, 2
        )
        $cycleCount = $design.CycleCount
    } else {
        $healthPercent = "Not Available"
        $cycleCount = "Not Available"
    }
} catch {
    $healthPercent = "Not Supported"
    $cycleCount = "Not Supported"
}

$endpointHealth | Add-Member -NotePropertyName "battery_health_percent" -NotePropertyValue $healthPercent -Force
$endpointHealth | Add-Member -NotePropertyName "battery_cycle_count" -NotePropertyValue $cycleCount -Force

# --- CPU utilization trend (60s sample, 1s interval) ---
try {
    $cpuSamples = Get-Counter '\Processor(_Total)\% Processor Time' -SampleInterval 1 -MaxSamples 60
    $cpuValues = $cpuSamples.CounterSamples | Select-Object -ExpandProperty CookedValue
    $cpuAvg = [math]::Round(($cpuValues | Measure-Object -Average).Average, 2)
    $cpuMax = [math]::Round(($cpuValues | Measure-Object -Maximum).Maximum, 2)
} catch {
    $cpuAvg = $null
    $cpuMax = $null
}

$endpointHealth | Add-Member -NotePropertyName "cpu_avg_60s" -NotePropertyValue $cpuAvg -Force
$endpointHealth | Add-Member -NotePropertyName "cpu_max_60s" -NotePropertyValue $cpuMax -Force

# --- Memory pressure (RAM usage %) ---
try {
    $os = Get-CimInstance Win32_OperatingSystem
    $totalKB = [float]$os.TotalVisibleMemorySize
    $freeKB  = [float]$os.FreePhysicalMemory
    $usedPct = [math]::Round((($totalKB - $freeKB) / $totalKB) * 100, 2)
} catch {
    $usedPct = $null
}

$endpointHealth | Add-Member -NotePropertyName "memory_used_percent" -NotePropertyValue $usedPct -Force

# --- SMART disk health (basic) ---
try {
    $smart = Get-WmiObject -Namespace root\wmi -Class MSStorageDriver_FailurePredictStatus | Select-Object -First 1
    if ($smart) {
        $smartPredictFailure = [bool]$smart.PredictFailure
        $smart_health = if ($smartPredictFailure) { "Failing" } else { "OK" }
    } else {
        $smart_health = "Not Available"
    }
} catch {
    $smart_health = "Not Supported"
    $smartPredictFailure = $null
}

$endpointHealth | Add-Member -NotePropertyName "smart_health" -NotePropertyValue $smart_health -Force
$endpointHealth | Add-Member -NotePropertyName "smart_predict_failure" -NotePropertyValue $smartPredictFailure -Force


# Export to JSON
$outputPath = "$PSScriptRoot\endpoint_health.json"
$endpointHealth | ConvertTo-Json -Depth 3 | Out-File $outputPath -Encoding UTF8

Write-Host "Endpoint health data collected successfully."
Write-Host "Output file: $outputPath"
