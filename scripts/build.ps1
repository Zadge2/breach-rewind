param([string]$Output = 'bin/rewind.exe')
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
function Invoke-Checked { param([string]$Program,[string[]]$Arguments) & $Program @Arguments; if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" } }
Push-Location $root
try {
    Push-Location (Join-Path $root 'web')
    try { Invoke-Checked npm @('ci'); Invoke-Checked npm @('run','build') } finally { Pop-Location }
    Invoke-Checked go @('mod','download')
    Invoke-Checked go @('vet','./...')
    $target = [IO.Path]::GetFullPath((Join-Path $root $Output))
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $target) | Out-Null
    Invoke-Checked go @('build','-trimpath','-ldflags=-s -w','-o',$target,'./cmd/rewind')
    Write-Output "Built $target"
} finally { Pop-Location }
