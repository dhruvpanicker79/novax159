<#
    Bring the whole thing up from a clean checkout. One command.

        .\run.ps1              build anything missing, train if needed, serve
        .\run.ps1 -Fresh       rebuild the corpus and retrain from scratch
        .\run.ps1 -Check       build and verify, but do not start the server
        .\run.ps1 -NoTrain     skip training; the rule-derived baseline ships

    The PowerShell twin of run.sh, for the Windows machines this team uses.
    Everything is idempotent: a warm checkout starts the server in a second.
#>
[CmdletBinding()]
param(
    [switch]$Fresh,
    [switch]$Check,
    [switch]$NoTrain
)

$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = if ($env:PYTHON) { $env:PYTHON } else { "python" }

function Step($text) { Write-Host "`n==> $text" -ForegroundColor White }
function Ok($text)   { Write-Host "    $text" -ForegroundColor Green }
function Warn($text) { Write-Host "    $text" -ForegroundColor Yellow }

# --------------------------------------------------------------------------- #
Step "Checking Python and dependencies"
& $py --version

# Test the call path, not the import: `import x` succeeding has repeatedly
# meant nothing on these machines, where Smart App Control blocks the compiled
# half of a package while the Python half imports fine (CLAUDE.md section 5).
& $py -c "import dpkt, io; dpkt.pcap.Writer(io.BytesIO())" 2>$null
if ($LASTEXITCODE -ne 0) {
    Warn "dpkt missing or unusable - installing"
    & $py -m pip install --quiet dpkt
}
Ok "dpkt works"

& $py -c "import flask; flask.Flask(__name__)" 2>$null
if ($LASTEXITCODE -ne 0) {
    Warn "flask missing - installing"
    & $py -m pip install --quiet flask
}
Ok "flask works"

# --------------------------------------------------------------------------- #
Step "Building the test corpus"
if ($Fresh) {
    foreach ($p in "testbed/out", "testbed/certs", "models") {
        if (Test-Path $p) { Remove-Item -Recurse -Force $p }
    }
    if (Test-Path "data/corpus.csv") { Remove-Item -Force "data/corpus.csv" }
}

if (-not (Test-Path "testbed/certs/_ca.der")) {
    & $py testbed/certgen.py | Out-Null
    Ok "certificates generated"
} else { Ok "certificates already present" }

if (-not (Test-Path "testbed/out/fleet.pcap")) {
    & $py testbed/synth.py --out testbed/out | Out-Null
    Ok "captures written"
} else { Ok "captures already present" }

if (-not (Test-Path "testbed/out/fleet_sll.pcap")) {
    & $py testbed/relink.py | Out-Null
    Ok "link-layer variants written"
} else { Ok "link-layer variants already present" }

# --------------------------------------------------------------------------- #
if (-not $NoTrain) {
    Step "Training the model"

    if (-not (Test-Path "data/corpus.csv")) {
        & $py -m securemailscope.ml.corpus | Out-Null
        # Verify, do not assume. This step silently did nothing for a while,
        # because ml/corpus.py had no __main__ block: the command exited 0
        # having written no corpus, and the failure surfaced later as a much
        # more reassuring message about the model losing to the baseline.
        if (-not (Test-Path "data/corpus.csv")) {
            Write-Host "    ERROR: data/corpus.csv was not written." -ForegroundColor Red
            Write-Host "    Run it directly to see why: $py -m securemailscope.ml.corpus" -ForegroundColor Red
            exit 1
        }
        Ok "training corpus generated"
    } else { Ok "training corpus already present" }

    if (-not (Test-Path "models/risk_model.json")) {
        # Pure Python, about ten seconds. No numpy, no scikit-learn, no Colab.
        # Exit 1 means the model lost to the rule-derived baseline and the
        # baseline ships, which is a real result. Anything else is a genuine
        # failure and must not be reported as the former.
        & $py scripts/train_local.py
        switch ($LASTEXITCODE) {
            0 { Ok "model trained" }
            3 { Warn "model did not beat the baseline - the baseline ships (this is fine)" }
            default {
                Write-Host "    ERROR: training failed (exit $LASTEXITCODE)" -ForegroundColor Red
                exit $LASTEXITCODE
            }
        }
    } else { Ok "model already trained (use -Fresh to retrain)" }
} else {
    Warn "skipping training - the rule-derived baseline will be used"
}

# --------------------------------------------------------------------------- #
Step "Generating the reports"
# Not cosmetic: D20, D21 and USP-06 are audited by reading the rendered
# artifacts, not by inspecting the renderer. Without this step a fresh clone
# audits three deliverables lower than the same code on a warm checkout.
if ((-not (Test-Path "out/report.json")) -or $Fresh) {
    & $py scripts/analyse.py testbed/out/fleet.pcap --out out/ --trust testbed/certs/_ca.der | Out-Null
    Ok "report.json, report.html and the four persona views written to out/"
} else { Ok "reports already present" }

# USP-07 is audited from this file, so write it rather than only printing it.
& $py scripts/evaluate.py --json out/evaluation.json 2>$null | Out-Null
Ok "evaluation written to out/evaluation.json"

# --------------------------------------------------------------------------- #
Step "Verifying"
& $py scripts/audit.py | Select-Object -Last 4
Write-Host ""
& $py scripts/evaluate.py | Select-Object -Last 8

if ($Check) {
    Step "Done (-Check: not starting the server)"
    exit 0
}

# --------------------------------------------------------------------------- #
Step "Starting the console on http://127.0.0.1:8000"
Write-Host "    sign in:  analyst / analyst123   (triage)"
Write-Host "              admin   / admin123     (triage + sign-off)"
Write-Host "    stop:     Ctrl-C"
Write-Host ""
& $py -m securemailscope.api
