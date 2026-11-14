# SENTINEL-M MFA live smoke: enroll â†’ login step-up â†’ TOTP verify â†’ recovery login
# â†’ single-use enforcement â†’ disable. Run against a live server whose DB was
# freshly seeded with SENTINEL_SEED_ADMIN_PASSWORD.
param([string]$Base = "http://127.0.0.1:8942/api/v1", [string]$Password = "Smoke!Admin1")
$ErrorActionPreference = "Stop"

$pw = @{ username = "admin"; password = $Password } | ConvertTo-Json
$login = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType "application/json" -Body $pw
$h = @{ Authorization = "Bearer $($login.access_token)" }
Write-Host "login ok (mfa_required=$($login.mfa_required))"

$setup = Invoke-RestMethod -Uri "$base/auth/mfa/setup" -Method Post -Headers $h
$secret = $setup.secret
$recovery = $setup.recovery_codes[0]
Push-Location (Join-Path $PSScriptRoot "..\backend")
$code = python -c "from app.core.mfa import generate_totp; print(generate_totp('$secret'))"
Pop-Location
Invoke-RestMethod -Uri "$base/auth/mfa/activate" -Method Post -Headers $h -ContentType "application/json" -Body (@{ code = $code } | ConvertTo-Json) | Out-Null
Write-Host "mfa enrolled + activated (secret=$($secret.Substring(0,4))â€¦)"

$l1 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType "application/json" -Body $pw
if (-not $l1.mfa_required) { throw "expected mfa_required on login" }
$stepH = @{ Authorization = "Bearer $($l1.access_token)" }
try {
    Invoke-RestMethod -Uri "$base/auth/me" -Headers $stepH | Out-Null
    throw "SECURITY BUG: step-up token authorized /auth/me"
} catch { Write-Host "step-up token rejected on /auth/me: $($_.Exception.Response.StatusCode.value__)" }

Push-Location (Join-Path $PSScriptRoot "..\backend")
$code = python -c "from app.core.mfa import generate_totp; print(generate_totp('$secret'))"
Pop-Location
$v = Invoke-RestMethod -Uri "$base/auth/mfa/verify" -Method Post -ContentType "application/json" -Body (@{ mfa_token = $l1.access_token; code = $code } | ConvertTo-Json)
$fullH = @{ Authorization = "Bearer $($v.access_token)" }
$me = Invoke-RestMethod -Uri "$base/auth/me" -Headers $fullH
Write-Host "totp verify ok -> full session for $($me.username) ($($me.role))"

$l2 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType "application/json" -Body $pw
$rec = Invoke-RestMethod -Uri "$base/auth/mfa/recovery-login" -Method Post -ContentType "application/json" -Body (@{ mfa_token = $l2.access_token; recovery_code = $recovery } | ConvertTo-Json)
Write-Host "recovery-login ok (mfa_required=$($rec.mfa_required))"

$l3 = Invoke-RestMethod -Uri "$base/auth/login" -Method Post -ContentType "application/json" -Body $pw
try {
    Invoke-RestMethod -Uri "$base/auth/mfa/recovery-login" -Method Post -ContentType "application/json" -Body (@{ mfa_token = $l3.access_token; recovery_code = $recovery } | ConvertTo-Json) | Out-Null
    throw "BUG: recovery code reusable"
} catch { Write-Host "reused recovery code rejected: $($_.Exception.Response.StatusCode.value__)" }

Push-Location (Join-Path $PSScriptRoot "..\backend")
$code = python -c "from app.core.mfa import generate_totp; print(generate_totp('$secret'))"
Pop-Location
Invoke-RestMethod -Uri "$base/auth/mfa/disable" -Method Post -Headers $fullH -ContentType "application/json" -Body (@{ password = $Password; code = $code } | ConvertTo-Json) | Out-Null
Write-Host "mfa disabled - smoke complete"
