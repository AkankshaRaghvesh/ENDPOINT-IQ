# Step 4: Plain-English Summary

$inputPath = "$PSScriptRoot\endpoint_health_scored.json"
$data = Get-Content $inputPath | ConvertFrom-Json

$issues = @()

if ($data.system_drive_free_percent -lt 10) {
    $issues += "Low disk space on C: drive"
}
if ($data.pending_reboot) {
    $issues += "Pending system reboot"
}
if ($data.defender_realtime_protection -eq "Off") {
    $issues += "Microsoft Defender real-time protection is disabled"
}
if (-not $data.bitlocker_enabled) {
    $issues += "BitLocker encryption is not enabled"
}

$summary = if ($issues.Count -eq 0) {
    "Endpoint is healthy. No immediate action required."
} else {
    "Issues detected: " + ($issues -join "; ") +
    ". Recommended action: address these items in order of risk severity."
}

$data | Add-Member -NotePropertyName remediation_summary -NotePropertyValue $summary

$outputPath = "$PSScriptRoot\endpoint_health_final.json"
$data | ConvertTo-Json -Depth 4 | Out-File $outputPath -Encoding UTF8

Write-Host "Summary generated."
Write-Host "Output file: $outputPath"
