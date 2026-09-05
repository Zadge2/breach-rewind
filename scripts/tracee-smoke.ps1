$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$suffix=[Guid]::NewGuid().ToString('N').Substring(0,10)
$fixture="breach-rewind-fixture-$suffix"
$tracer="breach-rewind-tracee-$suffix"
$createdFixture=$false
$createdTracer=$false
Push-Location $root
try {
    $out=Join-Path $root "artifacts/kernel-$suffix"
    New-Item -ItemType Directory -Path $out | Out-Null
    docker compose build vulnerable
    if($LASTEXITCODE -ne 0){throw 'Fixture image build failed'}
    $id=docker run -d --name $fixture --network none --read-only --tmpfs '/tmp:size=32m,mode=1777' --cap-drop ALL --security-opt no-new-privileges:true --pids-limit 32 --memory 128m --entrypoint python breach-rewind-lab-vulnerable -I -c 'import time; time.sleep(120)'
    if($LASTEXITCODE -ne 0){throw 'Fixture creation failed'}
    $createdFixture=$true
    $id=$id.Trim()
    docker run -d --name $tracer --pid=host --cgroupns=host --privileged -p '127.0.0.1::3366' -v /etc/os-release:/etc/os-release-host:ro -v /var/run/docker.sock:/var/run/docker.sock:ro --mount "type=bind,source=$out,target=/evidence" aquasec/tracee:0.24.1@sha256:cfbbfee972e64a644f6b1bac74ee26998e6e12442697be4c797ae563553a2a5b --scope "container=$id" --events sched_process_exec,openat,connect --output json:/evidence/tracee.jsonl --server http-address=0.0.0.0:3366 --server healthz
    if($LASTEXITCODE -ne 0){throw 'Tracee launch failed'}
    $createdTracer=$true
    $address=(docker port $tracer 3366/tcp).Trim()
    $ready=$false
    for($i=0;$i -lt 30;$i++) { try { $r=Invoke-WebRequest -Uri "http://$address/healthz" -TimeoutSec 2; if($r.StatusCode -eq 200){$ready=$true;break} } catch {}; if((docker inspect --format '{{.State.Running}}' $tracer).Trim() -ne 'true'){docker logs $tracer;throw 'Tracee exited during startup'}; Start-Sleep -Milliseconds 500 }
    if(!$ready){throw 'Tracee readiness timed out'}
    docker exec $fixture python -I /lab/scenario.py --scenario diagnostic-export --mode vulnerable | Out-File -Encoding utf8NoBOM (Join-Path $out 'native.jsonl')
    if($LASTEXITCODE -ne 0){throw 'Fixture execution failed'}
    docker stop --timeout 5 $tracer | Out-Null
    docker logs $tracer 2>&1 | Out-File -Encoding utf8NoBOM (Join-Path $out 'tracee.log')
    $events=Join-Path $out 'tracee.jsonl'
    if(!(Test-Path -LiteralPath $events) -or (Get-Item -LiteralPath $events).Length -eq 0){throw 'No kernel events captured'}
    go run ./cmd/rewind record --format tracee --input $events --title 'Scoped kernel diagnostic export' --db (Join-Path $out 'evidence.db')
    if($LASTEXITCODE -ne 0){throw 'Kernel import failed'}
    Write-Output "Kernel capture verified: $out"
} finally {
    if($createdTracer){docker rm -f $tracer | Out-Null}
    if($createdFixture){docker rm -f $fixture | Out-Null}
    Pop-Location
}
