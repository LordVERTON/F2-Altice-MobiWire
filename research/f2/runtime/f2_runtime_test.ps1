# Compatibility entry point. Pass explicit -Mode for automation, -Menu for a terminal menu.
& (Join-Path $PSScriptRoot '..\..\..\f2_runtime\f2_runtime_test.ps1') @args
exit $LASTEXITCODE
