# Step 3: Risk Scoring

# Load endpoint data
$inputPath = "$PSScriptRoot\endpoint_health.json"
$data = Get-Content $inputPath | ConvertFrom-Json

$score = 0

# Scoring rules
if ($data.system_drive_free_percent -lt 10) { $score += 15 }
if ($data.pending_reboot -eq $true) { $score += 10 }
if ($data.defender_realtime_protection -eq "Off") { $score += 25 }
if ($data.bitlocker_enabled -eq $false) { $score += 20 }

$lastPatchDate = Get-Date $data.last_update_installed_date
if ((New-TimeSpan -Start $lastPatchDate -End (Get-Date)).Days -gt 30) {
    $score += 15
}

# Severity
if ($score -ge 40) {
    $severity = "High"
} elseif ($score -ge 20) {
    $severity = "Medium"
} else {
    $severity = "Low"
}

# Add results
$data | Add-Member -NotePropertyName risk_score -NotePropertyValue $score
$data | Add-Member -NotePropertyName risk_severity -NotePropertyValue $severity

# Save updated JSON
$outputPath = "$PSScriptRoot\endpoint_health_scored.json"
$data | ConvertTo-Json -Depth 4 | Out-File $outputPath -Encoding UTF8

Write-Host "Risk scoring complete."
Write-Host "Output file: $outputPath"
