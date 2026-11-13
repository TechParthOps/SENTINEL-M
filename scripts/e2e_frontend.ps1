# Frontend E2E: serves the built SPA against the live API through the dev proxy.
# Verifies: SPA shell loads, login through the proxy, authenticated API call through the proxy.
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
$backend = Join-Path $root "backend"
$frontend = Join-Path $root "frontend"

$env:SENTINEL_SECRET_KEY = "smoke-test-key-0123456789abcdef"
$env:SENTINEL_SEED_ADMIN_PASSWORD = "Smoke!Admin1"

# free, deterministic ports for CI-style verification (8000 may be taken by other software)
$apiPort = 8951
$webPort = 5175
$env:VITE_API_TARGET = "http://127.0.0.1:$apiPort"
$env:VITE_WS_TARGET = "ws://127.0.0.1:$apiPort"

$api_ = Start-Process -PassThru -FilePath "python" -ArgumentList @("-m","uvicorn","app.main:app","--port","$apiPort") -WorkingDirectory $backend -WindowStyle Hidden
$web = Start-Process -PassThru -FilePath "node" -ArgumentList @("node_modules/vite/bin/vite.js","--port","$webPort","--strictPort","--host","127.0.0.1") -WorkingDirectory $frontend -WindowStyle Hidden

$up = $false
$lastErr = ""
for ($i = 0; $i -lt 40; $i++) {
    Start-Sleep -Milliseconds 1000
    try { $probe = Invoke-RestMethod -Uri "http://127.0.0.1:$webPort/" -TimeoutSec 3; $up = $true; break } catch { $lastErr = $_.Exception.Message }
}
if (-not $up) {
    Write-Host "web.HasExited=$($web.HasExited) api.HasExited=$($api_.HasExited) lastErr=$lastErr"
    Stop-Process -Id $api_.Id, $web.Id -Force -ErrorAction SilentlyContinue
    throw "frontend dev server did not start on port $webPort"
}

try {
    $html = (Invoke-WebRequest -Uri "http://127.0.0.1:$webPort/" -UseBasicParsing).Content
    if ($html -notmatch '<div id="root">') { throw "SPA shell missing" }
    Write-Host "E2E frontend shell served"

    $login = Invoke-RestMethod -Uri "http://127.0.0.1:$webPort/api/v1/auth/login" -Method Post -ContentType "application/json" -Body (@{username="admin";password="Smoke!Admin1"}|ConvertTo-Json)
    Write-Host "E2E proxied login: $($login.username) / $($login.role)"

    $h = @{ Authorization = "Bearer $($login.access_token)" }
    $stats = Invoke-RestMethod -Uri "http://127.0.0.1:$webPort/api/v1/stats/overview" -Headers $h
    Write-Host "E2E proxied stats: events=$($stats.events.total) assets=$($stats.assets.total)"

    $rules = Invoke-RestMethod -Uri "http://127.0.0.1:$webPort/api/v1/rules" -Headers $h
    Write-Host "E2E proxied rules: $($rules.total)"

    # SPA route fallback: deep link must still serve the app shell
    $deep = (Invoke-WebRequest -Uri "http://127.0.0.1:$webPort/incidents" -UseBasicParsing).Content
    if ($deep -notmatch '<div id="root">') { throw "SPA deep-link fallback broken" }
    Write-Host "E2E SPA deep-link fallback OK"
    Write-Host "E2E COMPLETE"
}
finally {
    Stop-Process -Id $api_.Id, $web.Id -Force -ErrorAction SilentlyContinue
    Get-CimInstance Win32_Process -Filter "Name='node.exe'" | Where-Object { $_.CommandLine -match "vite" } | ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
}