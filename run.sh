#!/usr/bin/env bash
# Bring the whole thing up from a clean checkout. One command.
#
#   ./run.sh              build anything missing, train if needed, serve
#   ./run.sh --fresh      rebuild the corpus and retrain from scratch
#   ./run.sh --check      build and verify, but do not start the server
#   ./run.sh --no-train   skip training; the rule-derived baseline ships
#
# Everything here is idempotent: steps that have already been done are skipped,
# so re-running it on a warm checkout starts the server in about a second.
#
# On Windows use `run.ps1`, or run this under Git Bash.

set -euo pipefail
cd "$(dirname "$0")"

PY="${PYTHON:-python}"
FRESH=0; CHECK_ONLY=0; TRAIN=1
for arg in "$@"; do
  case "$arg" in
    --fresh)    FRESH=1 ;;
    --check)    CHECK_ONLY=1 ;;
    --no-train) TRAIN=0 ;;
    -h|--help)  sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $arg  (try --help)" >&2; exit 2 ;;
  esac
done

step() { printf '\n\033[1m==> %s\033[0m\n' "$1"; }
ok()   { printf '    \033[32m%s\033[0m\n' "$1"; }
warn() { printf '    \033[33m%s\033[0m\n' "$1"; }

# --------------------------------------------------------------------------- #
step "Checking Python and dependencies"
$PY --version

# dpkt is the only hard requirement for analysis; flask only for the console.
# Test the *call path*, not the import — `import x` succeeding has repeatedly
# meant nothing on these machines (CLAUDE.md §5).
if ! $PY -c "import dpkt, io; dpkt.pcap.Writer(io.BytesIO())" >/dev/null 2>&1; then
  warn "dpkt missing or unusable — installing"
  $PY -m pip install --quiet dpkt
fi
ok "dpkt works"

if ! $PY -c "import flask; flask.Flask(__name__)" >/dev/null 2>&1; then
  warn "flask missing — installing"
  $PY -m pip install --quiet flask
fi
ok "flask works"

# --------------------------------------------------------------------------- #
step "Building the test corpus"
if [ "$FRESH" = 1 ]; then
  rm -rf testbed/out testbed/certs data/corpus.csv models
fi

if [ ! -f testbed/certs/_ca.der ]; then
  $PY testbed/certgen.py >/dev/null
  ok "certificates generated"
else
  ok "certificates already present"
fi

if [ ! -f testbed/out/fleet.pcap ]; then
  $PY testbed/synth.py --out testbed/out >/dev/null
  ok "captures written"
else
  ok "captures already present"
fi

if [ ! -f testbed/out/fleet_sll.pcap ]; then
  $PY testbed/relink.py >/dev/null
  ok "link-layer variants written"
else
  ok "link-layer variants already present"
fi

# --------------------------------------------------------------------------- #
if [ "$TRAIN" = 1 ]; then
  step "Training the model"
  if [ ! -f data/corpus.csv ]; then
    $PY -m securemailscope.ml.corpus >/dev/null
    ok "training corpus generated"
  fi
  if [ ! -f models/risk_model.json ]; then
    # Pure Python, about ten seconds. No numpy, no scikit-learn, no Colab.
    # If it loses to the rule-derived baseline it refuses to write, and the
    # baseline is what ships — that is a real result, not a failure.
    if $PY scripts/train_local.py; then
      ok "model trained"
    else
      warn "model did not beat the baseline — the baseline ships (this is fine)"
    fi
  else
    ok "model already trained (use --fresh to retrain)"
  fi
else
  warn "skipping training — the rule-derived baseline will be used"
fi

# --------------------------------------------------------------------------- #
step "Verifying"
$PY scripts/audit.py | tail -4
echo
$PY scripts/evaluate.py | tail -8

if [ "$CHECK_ONLY" = 1 ]; then
  step "Done (--check: not starting the server)"
  exit 0
fi

# --------------------------------------------------------------------------- #
step "Starting the console on http://127.0.0.1:8000"
echo "    sign in:  analyst / analyst123   (triage)"
echo "              admin   / admin123     (triage + sign-off)"
echo "    stop:     Ctrl-C"
echo
exec $PY -m securemailscope.api
