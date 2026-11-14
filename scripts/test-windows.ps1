$ErrorActionPreference = 'Stop'
$root = Join-Path $env:RUNNER_TEMP 'eightctl-windows-proof'
New-Item -ItemType Directory -Force $root | Out-Null
$config = Join-Path $root 'config.yaml'
Set-Content -Path $config -Value 'timezone: Europe/Vienna'
$beforeHash = (Get-FileHash $config).Hash
$beforeAcl = (Get-Acl $config).Sddl
$env:CGO_ENABLED = '0'
$env:EIGHTCTL_WINDOWS_PROOF = '1'
tzutil /s 'Pacific Standard Time'
if ($LASTEXITCODE -ne 0) { throw 'tzutil failed' }
go build -o "$root/head.exe" ./cmd/eightctl
if ($LASTEXITCODE -ne 0) { throw 'head build failed' }
$output = (& "$root/head.exe" version --config $config 2>&1 | Out-String)
if ($LASTEXITCODE -ne 0 -or $output -match 'permiss|mode 6') { throw "unexpected config warning: $output" }
if ((Get-FileHash $config).Hash -ne $beforeHash -or (Get-Acl $config).Sddl -ne $beforeAcl) { throw 'config content or ACL changed' }
Write-Output 'Windows CLI loaded existing config without Unix-mode warning; bytes and ACL unchanged.'
go test ./internal/config ./internal/cmd -run 'TestWarnInsecurePerms|TestWindowsSystemTimezone' -count=1 -v
if ($LASTEXITCODE -ne 0) { throw 'Windows head tests failed' }
Copy-Item internal/cmd/windows_runtime_test.go baseline/internal/cmd/windows_runtime_test.go
Push-Location baseline
try {
 go build -o "$root/base.exe" ./cmd/eightctl
 if ($LASTEXITCODE -ne 0) { throw 'baseline build failed' }
 $oldOutput = (& "$root/base.exe" version --config $config 2>&1 | Out-String)
 if ($oldOutput -notmatch 'permiss') { throw 'baseline did not reproduce permission warning' }
 Write-Output 'Baseline Windows CLI reproduces Unix permission warning.'
 $oldTimezone = (go test ./internal/cmd -run TestWindowsSystemTimezone -count=1 -v 2>&1 | Out-String)
 if ($LASTEXITCODE -eq 0 -or $oldTimezone -notmatch 'system timezone = "UTC"') { throw "baseline did not reproduce UTC fallback: $oldTimezone" }
 $global:LASTEXITCODE = 0
 Write-Output 'Baseline Windows timezone regression failed as expected.'
} finally { Pop-Location }
