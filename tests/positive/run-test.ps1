$ErrorActionPreference = 'Continue'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$root = Resolve-Path (Join-Path $here '..\..')
$scanner = Join-Path $root 'dist\AgentScan.exe'
if (-not (Test-Path $scanner)) { throw "Нет $scanner - сначала запустите build.cmd" }

$home21 = $env:JAVA_HOME
if (-not $home21) {
    $line = cmd /c "java -XshowSettings:properties -version 2>&1" | Where-Object { $_ -match '^\s*java\.home\s*=' }
    $home21 = ($line -replace '^\s*java\.home\s*=\s*', '').Trim()
}
$jdk = Join-Path $home21 'bin'
$javac = Join-Path $jdk 'javac.exe'; $jar = Join-Path $jdk 'jar.exe'; $java = Join-Path $jdk 'java.exe'

$work = Join-Path $here 'out'
$classes = Join-Path $work 'classes'
New-Item -ItemType Directory -Force $classes | Out-Null
& $javac -d $classes (Join-Path $here 'Target.java') (Join-Path $here 'TestAgent.java') (Join-Path $here 'Attacher.java')
if ($LASTEXITCODE -ne 0) { throw "javac завершился с кодом $LASTEXITCODE" }
$agentJar = Join-Path $work 'agent.jar'
Push-Location $classes
& $jar cfm $agentJar (Join-Path $here 'agent-manifest.txt') 'TestAgent.class' 'TestAgent$Spy.class'
$jarExit = $LASTEXITCODE
Pop-Location
if ($jarExit -ne 0) { throw "jar завершился с кодом $jarExit" }

$procs = [ordered]@{}
$procs.clean = Start-Process $java -ArgumentList "-cp `"$classes`" Target" -PassThru -WindowStyle Hidden
$procs.premain = Start-Process $java -ArgumentList "-javaagent:`"$agentJar`" -cp `"$classes`" Target" -PassThru -WindowStyle Hidden
$procs.attach = Start-Process $java -ArgumentList "-cp `"$classes`" Target" -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 3
& $java -cp $classes Attacher $procs.attach.Id $agentJar
Start-Sleep -Seconds 1

$reports = Join-Path $work 'reports'
try {
    foreach ($k in $procs.Keys) {
        $p = $procs[$k]
        Write-Host ""
        Write-Host "===== $k (PID $($p.Id))" -ForegroundColor Cyan
        & $scanner --pid $p.Id --no-dump --out $reports 2>$null |
            Select-String -Pattern 'Критических:|●|ВЫВОД' | ForEach-Object { $_.Line }
        Write-Host "код возврата: $LASTEXITCODE"
    }
}
finally {
    foreach ($p in $procs.Values) { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue }
}
Write-Host ""
Write-Host "Отчёты: $reports"
