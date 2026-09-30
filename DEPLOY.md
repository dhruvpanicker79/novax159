# Deploying Kavach

The console is a Flask app served by **waitress** (pure Python, no build
toolchain), with SQLite for state. Everything the demo needs — certificates,
the capture corpus, the trained model, the rendered reports — is built into the
image, so a container boots populated rather than empty.

---

## Render (recommended)

1. Push to GitHub (already done).
2. **render.com → New → Blueprint → connect `dhruvpanicker79/novax159`.**
3. Apply. Render reads `render.yaml` and builds the Dockerfile.

First build takes about **five minutes** — it generates RSA keys in pure
Python, builds the synthetic corpus and trains the model. Later builds reuse
cached layers. Auto-deploy is on, so pushing to `main` redeploys.

You get an HTTPS URL like `https://kavach.onrender.com`.

**Free-plan behaviour, so it is not a surprise on the day:**

- the service **spins down after ~15 minutes idle**, and the next request takes
  roughly 30 seconds to wake it. Hit the URL a minute before presenting;
- the disk is **ephemeral**, so uploads and triage decisions do not survive a
  restart. The app re-seeds the two bundled captures on every boot, so the demo
  is always populated and always identical. That is deliberate.

## Railway

Reads the `Procfile`. Set the same variables from `render.yaml` by hand.

## Anywhere else

```bash
docker build -t kavach .
docker run -p 8000:8000 kavach
```

---

## Environment variables

| Variable | Default | What it does |
|---|---|---|
| `PORT` | `8000` | Set by the platform |
| `HOST` | `0.0.0.0` | Containers must bind all interfaces |
| `SMS_SECRET` | generated per boot | Session signing key. **Set it**, or everyone is logged out on each restart |
| `SMS_BEHIND_TLS` | `1` | Marks the session cookie `Secure`. Set `0` for plain-HTTP local testing |
| `SMS_ADMIN_PASSWORD` | unset | Replaces the demo password. See below |
| `SMS_BRAND` | `Kavach` | The wordmark (the project name is still unsettled) |
| `SMS_MAX_UPLOAD` | 25 MB | The bundled captures are ~30 KB |
| `SMS_MAX_JOBS` | `40` | Older jobs and their uploads are pruned on boot |
| `SMS_LOGIN_ATTEMPTS` | `20` | Failed sign-ins per address per 5 minutes |

`GET /api/deployment` reports which of these are live. It needs no
authentication, and returns no capture data.

---

## What this deployment deliberately accepts

**The demo credentials are active**, and the login page prints them:

```
analyst / analyst123    triage
admin   / admin123      triage + sign-off
```

That is a choice, made so a judge can follow a link and sign in without being
handed a password. The consequence is real and worth stating plainly: **anyone
who finds the URL can sign in and upload a capture.**

The trade is defensible here because the data is synthetic, the parser is pure
Python with no `eval` and no untrusted deserialisation, and the realistic worst
case is resource abuse rather than compromise. The mitigations are sized for
exactly that:

- uploads capped at 25 MB and the oldest jobs pruned, so disk cannot run away;
- `/login` rate-limited per address, so a known password cannot be hammered;
- cookies `Secure` and `HttpOnly` behind the platform's TLS;
- only four routes are unauthenticated — `/api/health`, `/login`, `/logout`,
  `/static/*` — and `/api/health` returns liveness only, no capture data.

**To close it:** set `SMS_ADMIN_PASSWORD` in the Render dashboard and redeploy.
The seeder uses it instead of the default.

---

## Verifying a deployment

```bash
curl https://YOUR-URL/api/health        # {"status":"ok","jobs":2}
curl https://YOUR-URL/api/deployment    # which mode is live
```

Then sign in and check **Posture Drift** — it only renders when the boot seed
analysed both bundled captures, so it is a good single indicator that the
deployment came up correctly.

---

## Local

```bash
./run.sh                                 # dev server, port 8000
SMS_BEHIND_TLS=0 python -m securemailscope.api.production   # production server
```

`SMS_BEHIND_TLS=0` matters locally: with it set to `1` the session cookie is
marked `Secure` and a browser will not send it over plain HTTP, so sign-in
appears to silently fail.
