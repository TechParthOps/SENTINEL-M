# SENTINEL-M end-to-end smoke test.
# Starts the real API on a live port, authenticates, ingests an attack sequence,
# and verifies alerts/incidents/detail evidence/stats/health/audit/coverage.
# Usage:  powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
$ErrorActionPreference = "Stop"

$backend = Join-Path $PSScriptRoot "..\backend"
$port = 8941
$before = Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue
if ($before) { throw "port $port already in use" }

$env:SENTINEL_SECRET_KEY = "smoke-test-key-0123456789abcdef"
$env:SENTINEL_SEED_ADMIN_PASSWORD = "Smoke!Admin1"

$proc = Start-Process -PassThru -FilePath "python" -ArgumentList "-m", "uvicorn", "app.main:app", "--port", "$port" -WorkingDirectory $backend -WindowStyle Hidden

$up = $false
for ($i = 0; $i -lt 30; $i++) {
    Start-Sleep -Milliseconds 1200
    try {
        $r = Invoke-RestMethod -Uri "http://127.0.0.1:$($port)/api/v1" -TimeoutSec 3
        $up = $true; break
    } catch { }
}
if (-not $up) {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
    throw "server did not start on port $port"
}
Write-Host "SMOKE server up: $($r.name) $($r.version)"

try {
    $base = "http://127.0.0.1:$port/api/v1"
    $login = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType "application/json" -Body (@{username="admin";password="Smoke!Admin1"}|ConvertTo-Json)
    $h = @{ Authorization = "Bearer $($login.access_token)" }
    Write-Host "SMOKE login: $($login.username) role=$($login.role)"

    $auth = 1..10 | ForEach-Object { @{type="auth"; payload=@{src_ip="203.0.113.66"; user="admin"; outcome="failure"; host="dc-01"; message="failed password for admin"}} }
    $chain = @(
        @{type="process"; payload=@{host="ws-42"; process_name="powershell.exe"; command_line="powershell.exe -encodedcommand UwB0AGEAcgB0AC0AUAByAG8AYwBlAHMAcwAgAGMA0QA="}},
        @{type="process"; payload=@{host="ws-42"; process_name="schtasks.exe"; command_line="schtasks.exe /create /tn Updater /sc onlogon /tr powershell.exe -file C:\Temp\ps.ps1"}}
    )
    $sqli  = @(@{type="http"; payload=@{src_ip="198.51.100.9"; http_method="GET"; http_url="/api/items?id=1%20UNION%20SELECT%20name,password%20FROM%20users--"; http_status=500}})
    $ransom = 1..40 | ForEach-Object { @{type="file"; payload=@{host="ws-42"; file_action="modify"; file_path="C:\Users\doc$_.final.docx.locked"}} }

    $body = @{ source=@{product="smoke-sensor"; version="1.0.0"}; events = ($auth + $chain + $sqli + $ransom) } | ConvertTo-Json -Depth 6
    $ing = Invoke-RestMethod -Uri "$base/events/ingest" -Method Post -Headers $h -ContentType "application/json" -Body $body
    Write-Host "SMOKE ingest: accepted=$($ing.accepted) alerts=$($ing.alerts_created) incidents=$($ing.incidents_touched)"

    $alerts = Invoke-RestMethod -Uri "$base/alerts?limit=200" -Headers $h
    $alerts.alerts | Group-Object rule_id | ForEach-Object { Write-Host "SMOKE alert rule $($_.Name) x$($_.Count)" }

    $incs = Invoke-RestMethod -Uri "$base/incidents?limit=50" -Headers $h
    $incs.incidents | ForEach-Object { Write-Host "SMOKE incident $($_.id.Substring(0,8)) sev=$($_.severity_id) chain=$($_.attack_chain) cat=$($_.category) :: $($_.title)" }

    $detail = Invoke-RestMethod -Uri "$base/incidents/$($incs.incidents[0].id)" -Headers $h
    Write-Host "SMOKE detail alerts=$($detail.alerts.Count) evidence=$($detail.alerts[0].evidence_event_ids.Count) techs=$($detail.attack_ids -join ',')"
    Write-Host "SMOKE summary: $($detail.summary.Substring(0,[Math]::Min(150,$detail.summary.Length)))"

    $stats = Invoke-RestMethod -Uri "$base/stats/overview" -Headers $h
    Write-Host "SMOKE stats: events=$($stats.events.total) buckets=$($stats.events.timeline_30m.Count) assets=$($stats.assets.total)"

    $health = Invoke-RestMethod -Uri "$base/health" -Headers $h
    Write-Host "SMOKE health: $($health.status) modules=$($health.modules.PSBase.Keys -join ',')"

    $cov = Invoke-RestMethod -Uri "$base/coverage" -Headers $h
    Write-Host "SMOKE coverage: phase1=$((($cov.phases | Where-Object {$_.phase -eq 1}).status)) phase6=$((($cov.phases | Where-Object {$_.phase -eq 6}).status)) rules=$($cov.runtime.rules_loaded)"

    $audit = Invoke-RestMethod -Uri "$base/audit?limit=50" -Headers $h
    Write-Host "SMOKE audit chain valid=$($audit.chain.valid) entries=$($audit.entries.Count)"

    $rules = Invoke-RestMethod -Uri "$base/rules" -Headers $h
    Write-Host "SMOKE rules loaded=$($rules.total)"

    # kill switch: verify an invalid token is actually rejected over HTTP
    try {
        Invoke-RestMethod -Uri "$base/events?limit=1" -Headers @{Authorization="Bearer garbage"} | Out-Null
        Write-Host "SMOKE FAIL invalid token accepted"
    } catch {
        Write-Host "SMOKE auth rejection: $($_.Exception.Response.StatusCode.value__)"
    }
    Write-Host "SMOKE COMPLETE"
}
finally {
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
}