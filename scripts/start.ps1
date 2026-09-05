param([int]$Port = 9847,[string]$Python = 'python')
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$binary=Join-Path $root 'bin/rewind.exe'
if (!(Test-Path -LiteralPath $binary)) { & (Join-Path $PSScriptRoot 'build.ps1') }
Push-Location $root
try { & $binary serve --addr "127.0.0.1:$Port" --python $Python; if ($LASTEXITCODE -ne 0) { throw "Server exited with code $LASTEXITCODE" } } finally { Pop-Location }
