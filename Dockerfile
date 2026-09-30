# SecureMailScope / Kavach — deployable image.
#
# Everything the demo needs is built at *image build time*, not at boot:
# certificates, the synthetic capture corpus, the link-layer variants, the
# training corpus, the trained model, and the rendered reports. That matters on
# a free tier, where containers restart on idle and a cold start that spends
# ninety seconds generating RSA keys looks like a broken link.
#
# It also means the image is self-contained: `python scripts/audit.py` inside
# the container reports the same 32 met / 1 partial / 1 not built as a
# developer's machine, because the artifacts the audit reads are baked in.
#
#   docker build -t kavach .
#   docker run -p 8000:8000 kavach
#
# On Render or Railway nothing else is needed — they set $PORT and terminate
# TLS, and `securemailscope.api.production` reads both.

FROM python:3.11-slim

# Fail fast and log straight through, so a crash-looping container says why.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

# Dependencies first: this layer is cached unless requirements.txt changes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# --------------------------------------------------------------------------- #
# Build the corpus and the model into the image.
#
# certgen.py generates real RSA keys in pure Python, which is the slowest step
# here and the whole reason this is not done at boot.
RUN python testbed/certgen.py \
 && python testbed/synth.py --out testbed/out \
 && python testbed/relink.py \
 && python -m securemailscope.ml.corpus \
 && python scripts/train_local.py \
 && python scripts/analyse.py testbed/out/fleet.pcap --out out/ \
        --trust testbed/certs/_ca.der \
 && python scripts/evaluate.py --json out/evaluation.json

# Prove the image is what we think it is. A build that produced a broken
# artifact should fail here, not in front of a judge.
RUN python scripts/audit.py | tail -3 \
 && python tests/test_platform.py | tail -1 \
 && python tests/test_gbt.py | tail -1

# --------------------------------------------------------------------------- #
# Runtime state lives here. On a free tier this is ephemeral and the app
# re-seeds itself on boot, which is deliberate: the demo is always clean.
RUN mkdir -p data/uploads

EXPOSE 8000
ENV PORT=8000 \
    HOST=0.0.0.0 \
    SMS_BEHIND_TLS=1

# Not `flask run` and not `app.run()`: both are development servers.
CMD ["python", "-m", "securemailscope.api.production"]
