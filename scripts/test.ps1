param([ValidateRange(1,10)][int]$Repeat=3,[int]$Port=9853,[switch]$SkipBrowser,[switch]$SkipBuild)
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$server=$null
$oldUrl=$env:REWIND_URL
function Invoke-Checked { param([string]$Program,[string[]]$Arguments) & $Program @Arguments; if ($LASTEXITCODE -ne 0) { throw "$Program failed with exit code $LASTEXITCODE" } }
Push-Location $root
try {
    $results=Join-Path $root ('artifacts/verification-'+(Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Path $results -Force | Out-Null
    Start-Transcript -Path (Join-Path $results 'test-log.txt') | Out-Null
    if (!$SkipBuild) { & (Join-Path $PSScriptRoot 'build.ps1') -Output 'bin/rewind-test.exe' }
    Invoke-Checked go @('vet','./...')
    Invoke-Checked go @('test','-race','-shuffle=on',"-count=$Repeat","-coverprofile=$(Join-Path $results 'coverage.out')",'./...')
    Invoke-Checked go @('run','golang.org/x/vuln/cmd/govulncheck@v1.7.0','./...')
    Invoke-Checked python @('-m','unittest','discover','-s','sdk/python','-v')
    Push-Location (Join-Path $root 'web')
    try {
        Invoke-Checked npm @('test')
        Invoke-Checked npm @('audit','--audit-level=low')
        if (!$SkipBrowser) {
            Invoke-Checked npx @('playwright','install','chromium')
            $db=Join-Path $results 'browser.db'
            $server=Start-Process -FilePath (Join-Path $root 'bin/rewind-test.exe') -ArgumentList @('serve','--addr',"127.0.0.1:$Port",'--db',"`"$db`"") -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $results 'server.log') -RedirectStandardError (Join-Path $results 'server-error.log')
            $env:REWIND_URL="http://127.0.0.1:$Port"
            $ready=$false
            for($i=0;$i -lt 40;$i++) { if($server.HasExited){throw 'Test server exited before readiness'}; try { $response=Invoke-WebRequest -Uri "$env:REWIND_URL/api/health" -Headers @{'X-Rewind-Client'='1'} -TimeoutSec 2; if($response.StatusCode -eq 200){$ready=$true;break} } catch {}; Start-Sleep -Milliseconds 250 }
            if(!$ready){throw 'Test server readiness timed out'}
            Invoke-Checked npx @('playwright','test',"--repeat-each=$Repeat")
        }
    } finally { Pop-Location }
    Write-Output "All verification gates passed. Logs: $results"
} finally {
    if($server -and !$server.HasExited){Stop-Process -InputObject $server}
    $env:REWIND_URL=$oldUrl
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
    Pop-Location
}
