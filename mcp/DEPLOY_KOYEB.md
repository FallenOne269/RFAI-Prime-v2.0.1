# Deploying the RFAI Council MCP server on Koyeb

This guide puts the RFAI Council MCP server on Koyeb's free instance, so Sesame (or any MCP client) can reach it at `https://<your-app>.koyeb.app/mcp` and sign in with your owner passcode. It covers the free-tier limits, the one billing step that can cost money if you skip it, the settings the server needs, and how to check it once it is up.

Koyeb facts below come from Koyeb's own docs (pages last updated May 27, 2026), read on October 31, 2026. Check the pricing pages again before you enter a card: plans change.

## What the free tier gives you

Per Koyeb's [instance reference](https://www.koyeb.com/docs/reference/instances) and [pricing FAQ](https://www.koyeb.com/docs/faqs/pricing):

- **One free web service per organization**: 512 MB RAM, 0.1 vCPU, 2 GB SSD, in Frankfurt or Washington, D.C. only. Koyeb says you are never charged for the free web service.
- **Sleeps when idle**: it scales to zero after 1 hour with no traffic. The next request wakes it, so the first call after a quiet hour is slower.
- **No volumes, no custom scaling**: that is fine here, because this server writes nothing to disk.
- **HTTPS is automatic** on the generated `*.koyeb.app` domain, so no reverse proxy is needed. Koyeb terminates TLS and forwards to the container.

## Billing: avoid the one charge

Koyeb's [pricing FAQ](https://www.koyeb.com/docs/faqs/pricing) says:

- **A credit card is required** "to prevent fraud and abuse". Koyeb places a **$29 pre-authorization hold** to verify it and cancels it right away; your bank may take 7 to 21 days to release it.
- **Sign-up preselects the Pro plan ($29 a month).** If you enter a card with Pro selected, you are charged the prorated Pro amount for the rest of the month. **Pick the Starter plan before you enter the card.** Starter has no base cost and still includes the free instance ([organizations reference](https://www.koyeb.com/docs/reference/organizations)). If you end up on Pro, switch to Starter under Usage and billing.
- **There is no hard spending cap yet.** Koyeb offers billing alert emails at 80% and 100% of a threshold you set (minimum $5) on the Usage and billing page. Set one at $5 as a tripwire.
- **Stay on the Free instance type.** Any other instance size is billed per second.

Account validation after entering a card usually takes minutes but can take up to 3 business days.

## Before you start: make the two secrets on your own computer

The server refuses to start without these. Make them on a computer you trust, paste them only into Koyeb, and never into chat, email or the repository.

1. **Signing secret** (at least 32 random bytes). In a terminal:

   ```bash
   openssl rand -hex 32
   ```

2. **Owner passcode hash.** Choose a long passcode you will type on the sign-in page. Then, from a checkout of this repository with Node 22.18 or newer:

   ```bash
   cd mcp
   node scripts/hash-passcode.mjs
   ```

   It asks for the passcode without showing it and prints only a hash starting with `scrypt$`. That hash is what goes into Koyeb. The passcode itself is never stored anywhere.

Keep the passcode somewhere safe (a password manager). If you lose it, make a new hash and replace the secret in Koyeb.

## Step 1: Create the account

1. Go to [Koyeb sign-up](https://app.koyeb.com/auth/signup) and choose **Continue with GitHub** (easiest, because Koyeb then needs access to the `FallenOne269/RFAI-Prime-v2.0.1` repository anyway).
2. When asked for a plan, choose **Starter**, then add the card.
3. On Usage and billing, set a billing alert at $5.

## Step 2: Store the secrets in Koyeb

In the Koyeb control panel, open **Secrets** and create:

| Secret name | Value |
| --- | --- |
| `RFAI_MCP_SECRET` | the hex string from `openssl rand -hex 32` |
| `RFAI_MCP_OWNER_PASSCODE_HASH` | the `scrypt$...` line from the hash script |

Add `RFAI_LLM_KEY` later, when you have a Bankr model key (see Step 6).

Koyeb encrypts secret values and only services you attach them to can read them ([secrets reference](https://www.koyeb.com/docs/reference/secrets)).

## Step 3: Create the web service

In the control panel choose **Create Web Service**, then **GitHub**, and set:

| Setting | Value |
| --- | --- |
| Repository | `FallenOne269/RFAI-Prime-v2.0.1` |
| Branch | `mcp-oauth-server` until the pull request is merged, then `main` |
| Builder | **Dockerfile** |
| Work directory | `mcp` |
| Dockerfile location | `Dockerfile` |
| Instance | **Free** |
| Region | Washington, D.C. (or Frankfurt) |
| Exposed port | `8080`, protocol HTTP, public path `/` |
| Health check | HTTP, port `8080`, path `/healthz` |

The work directory matters: the Dockerfile expects the `mcp/` folder as its build context. Koyeb describes these fields on its [deploy with git page](https://www.koyeb.com/docs/build-and-deploy/deploy-with-git).

## Step 4: Environment variables

Under **Environment variables**, add these. The `{{ ... }}` values are Koyeb's own syntax: Koyeb fills in the app's domain and the secret values at deploy time ([environment variables reference](https://www.koyeb.com/docs/build-and-deploy/environment-variables)).

| Name | Value | Notes |
| --- | --- | --- |
| `RFAI_MCP_PUBLIC_URL` | `https://{{ KOYEB_PUBLIC_DOMAIN }}` | Must be the exact https origin clients use. If you add a custom domain later, put that origin here instead. |
| `RFAI_MCP_SECRET` | `{{ secret.RFAI_MCP_SECRET }}` | Required. |
| `RFAI_MCP_OWNER_PASSCODE_HASH` | `{{ secret.RFAI_MCP_OWNER_PASSCODE_HASH }}` | Required. |
| `RFAI_MCP_REFRESH_TTL_SECONDS` | `604800` | Recommended on the free tier: refresh tokens last 7 days instead of 30 (see the limits below). |

Leave everything else at its default. `PORT` is already 8080 in the image. Optional settings the server understands:

- `RFAI_MCP_TOKEN_EPOCH` (default `1`): change it to any new value, such as `2`, to sign every connected app out at once.
- `RFAI_MCP_MAX_RUNS_PER_HOUR` (default 20) and `RFAI_MCP_MAX_CONCURRENT_RUNS` (default 2): limits on `council_ask`.
- `RFAI_MCP_TRUST_PROXY_HOPS` (default 1): how many proxies sit in front of the server, used to find the caller's address for the passcode lockout. One hop is the expected value for Koyeb, but it has not been confirmed on Koyeb yet.
- `RFAI_TRUSTED_SIGNERS`: leave unset. With no trusted signers the council stays fully locked down and nothing can be overridden.
- `RFAI_ARCHITECT_MODEL`, `RFAI_CRITIC_MODEL`, `RFAI_INTEGRATOR_MODEL`: default to `claude-haiku-4.5`.

If a required value is missing or malformed, the deploy log names the variable and the problem (never the value) and the service will not start. That is intentional.

## Step 5: Deploy and check it

Click **Deploy**. When the service is healthy, note its domain (shown on the service page, in the form `<app>-<org>-<hash>.koyeb.app`) and check:

1. `https://<domain>/healthz` returns `{"ok":true}`.
2. `https://<domain>/.well-known/oauth-protected-resource/mcp` shows `"resource":"https://<domain>/mcp"`. If it shows a different address, `RFAI_MCP_PUBLIC_URL` is wrong and sign-in will fail.
3. The deploy log shows `RFAI Council MCP server listening on port 8080` and, until Step 6, a warning that `RFAI_LLM_KEY` is not set.

## Step 6: Connect Sesame

In Sesame's **Add custom app**, enter `https://<domain>/mcp`. Sesame opens the server's sign-in page; type your owner passcode and approve. Five wrong passcodes from one address, or ten from all addresses together, within 15 minutes pause sign-in for 15 minutes.

You then get three tools:

- `council_info`: version, policy, and whether a model key is set.
- `council_screen`: the governance check alone. Free, no model call.
- `council_ask`: the full governed council. Needs a model key.

## Step 7: Let the council answer

`council_ask` calls Bankr's model gateway (`https://llm.bankr.bot/v1/messages`). Until both of these are in place it refuses before any model call, and says so:

1. Add a Koyeb secret `RFAI_LLM_KEY` holding your Bankr model key, and an environment variable `RFAI_LLM_KEY` = `{{ secret.RFAI_LLM_KEY }}`. Redeploy.
2. Add LLM credits to your Bankr account. This is the only part of the setup that costs money, and it is billed by Bankr, not Koyeb.

## Free-tier limits that affect this server

The server keeps no database. Sign-ins are signed tokens, so they survive restarts and the free instance waking from sleep. A few safety counters live only in memory, though, and reset whenever the instance restarts or wakes:

- **Revoked and already-used refresh tokens** are remembered in memory. After a restart, a refresh token you revoked could work again until it expires. The 7-day refresh lifetime above limits that window. If you ever think a token leaked, change `RFAI_MCP_TOKEN_EPOCH` and redeploy: that signs out every app for good.
- **The passcode lockout** and the `council_ask` hourly limit reset on restart. An attacker's own traffic keeps the instance awake, so the lockout still holds during an attack.
- **Cold starts**: after an idle hour the first request waits for the container to start.

If you outgrow these limits, a paid instance with no sleep removes the cold starts; the in-memory counters would need a small database to survive restarts.

## How the container is built

- Two-stage build on `node:24-alpine3.24`, pinned by digest. Only production dependencies, installed exactly from `package-lock.json` with install scripts disabled.
- No build step: Node 24 runs the TypeScript sources directly.
- Runs as the unprivileged `node` user. App files are owned by root and read-only to it; npm is removed from the final image.
- `.dockerignore` admits only `package.json`, `package-lock.json` and `src/`, so tests, scripts, `.env` files and any local credentials never enter the build.
- No secrets in the image. Every credential arrives as an environment variable at run time.

To update the base image, look up the current digest of `node:24-alpine3.24` on Docker Hub and replace it on both `FROM` lines.

## What has and has not been checked

Checked locally on October 31, 2026, with Docker 29.1.3:

- The image builds, and with no settings it refuses to start and names the three missing variables.
- With throwaway settings it started read-only with all Linux capabilities dropped. `/healthz`, both OAuth discovery documents and the 401 challenge on `/mcp` all answered correctly.
- A full sign-in against the container worked: client registration, the passcode page (wrong passcode refused, right one accepted), PKCE token exchange, refusal to reuse the same code, then `initialize`, `tools/list` (three tools), `council_screen` (allowed a harmless request) and `council_ask` (refused cleanly with "model gateway not configured").
- The container log contained neither the passcode nor any token.
- The image runs as the `node` user, contains only `node_modules`, `package.json` and `src`, has no npm, and cannot write to `/app`.
- `npm test`: 29 of 29 passed on 10 runs in a row. `npm run typecheck` checks 13 source and test files and passes, and fails on a planted type error.

Not checked yet:

- Anything on Koyeb itself: the build there, the health check, `{{ KOYEB_PUBLIC_DOMAIN }}` filling in the URL, the proxy hop count, and wake-from-sleep timing.
- The Docker `HEALTHCHECK` line (the local sandbox could not run commands inside containers). Koyeb uses its own HTTP health check from Step 3 instead.
- A real `council_ask` with a model key and credits.
