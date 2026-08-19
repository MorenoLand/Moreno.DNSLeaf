param(
    [string]$Version = "dev",
    [string]$OutputDirectory = "",
    [string]$TargetOS = "windows",
    [string]$TargetArch = "amd64"
)

$ErrorActionPreference = "Stop"
$repositoryRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutputDirectory)) {
    $OutputDirectory = Join-Path $repositoryRoot "dist"
}
New-Item -ItemType Directory -Force -Path $OutputDirectory | Out-Null

$commitValue = "unknown"
try {
    $commitValue = (git -C $repositoryRoot rev-parse --short HEAD).Trim()
} catch {
}
$buildDateValue = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$ldflags = "-s -w -X main.version=$Version -X main.commit=$commitValue -X main.buildDate=$buildDateValue"
$extension = if ($TargetOS -eq "windows") { ".exe" } else { "" }
$artifactPath = Join-Path $OutputDirectory ("dnsleaf-{0}-{1}{2}" -f $TargetOS, $TargetArch, $extension)
$previousGOOS = $env:GOOS
$previousGOARCH = $env:GOARCH
try {
    $env:GOOS = $TargetOS
    $env:GOARCH = $TargetArch
    go build -mod=vendor -trimpath -ldflags $ldflags -o $artifactPath $repositoryRoot
} finally {
    $env:GOOS = $previousGOOS
    $env:GOARCH = $previousGOARCH
}
Write-Output ("built {0}" -f $artifactPath)
