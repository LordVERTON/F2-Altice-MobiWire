# Transient USB/COM observer — compatibility location

Current scripts, procedure, safety gates and findings are documented in [f2_runtime/README.md](../../../f2_runtime/README.md).

The three Python entry points and the PowerShell launcher here redirect to the current implementation. Existing historical captures and reports in this directory are preserved. New output goes to the repository-root `f2_runtime/` directory.

From the repository root:

```powershell
./f2_runtime_test.ps1 -Mode watch -PollMs 20 -DurationSec 90
```

Use `-Menu` for the numbered menu; default unattended mode is watch. Never run historical helper modules directly to open a device.
