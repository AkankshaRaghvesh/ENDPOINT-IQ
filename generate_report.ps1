# Step 5: Executive Endpoint Health Report

$inputPath = "$PSScriptRoot\endpoint_health_final.json"
$data = Get-Content $inputPath | ConvertFrom-Json

$report = @"
ENDPOINT HEALTH REPORT
=====================

Device Name      : $($data.device_name)
User             : $($data.username)
Collected At     : $($data.collected_at)

OS               : $($data.os_caption)
OS Version       : $($data.os_version)
OS Build         : $($data.os_build)
Last Boot        : $($data.last_boot_time)

Last Patch Date  : $($data.last_update_installed_date)
Pending Reboot   : $($data.pending_reboot)

Disk Free (C:)   : $($data.system_drive_free_percent)%

Defender Status  : $($data.defender_realtime_protection)
BitLocker        : $($data.bitlocker_enabled)

Risk Score       : $($data.risk_score)
Risk Severity    : $($data.risk_severity)

Summary:
$($data.remediation_summary)
"@

$outputPath = "$PSScriptRoot\Endpoint_Health_Report.txt"
$report | Out-File $outputPath -Encoding UTF8

Write-Host "Report created."
Write-Host "Output file: $outputPath"
