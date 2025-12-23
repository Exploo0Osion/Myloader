$ErrorActionPreference = "Stop"

param(
  [ValidateSet("build", "clean")]
  [string]$Action = "build"
)

Push-Location $PSScriptRoot
try {
  if ($Action -eq "clean") {
    cmd /c "build.bat clean"
  } else {
    cmd /c "build.bat"
  }
  exit $LASTEXITCODE
} finally {
  Pop-Location
}

