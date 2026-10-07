$ErrorActionPreference = 'Stop'

$deployDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$envFile = Join-Path $deployDir 'secure-agent.env.ps1'
$jarFile = Join-Path $deployDir 'secure-agent.jar'

if (-not (Test-Path $envFile)) {
    throw "Environment file not found: $envFile"
}

if (-not (Test-Path $jarFile)) {
    throw "Agent JAR not found: $jarFile"
}

. $envFile

if ([string]::IsNullOrWhiteSpace($env:JAVA_HOME)) {
    throw "JAVA_HOME is not configured."
}

if ([string]::IsNullOrWhiteSpace($env:SECURE_SERVER_BASE_URL)) {
    throw "SECURE_SERVER_BASE_URL is not configured."
}

if ([string]::IsNullOrWhiteSpace($env:SECURE_AGENT_API_KEY)) {
    throw "SECURE_AGENT_API_KEY is not configured."
}

$javaExe = Join-Path $env:JAVA_HOME 'bin\java.exe'

if (-not (Test-Path $javaExe)) {
    throw "Java executable not found: $javaExe"
}

Write-Host "[INFO] Server: $env:SECURE_SERVER_BASE_URL"

& $javaExe -jar $jarFile

if ($LASTEXITCODE -ne 0) {
    throw "Agent exited with code: $LASTEXITCODE"
}