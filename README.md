# OurCodex

OurCodex is a self-hosted Codex Responses API proxy with account pools, per-user access tokens, usage controls, and an admin dashboard. Users run the `ourcodex` wrapper, while the server selects an eligible ChatGPT OAuth account or OpenAI API key from their assigned pools.

> [!IMPORTANT]
> This project handles sensitive OpenAI credentials. Review OpenAI's current terms and your organization's policies before pooling or sharing subscription accounts. API keys are the clearest option for organizational usage. You are responsible for securing the deployment and using accounts within their applicable terms.

## How it works

The `ourcodex` command launches the installed `codex` CLI with a temporary custom model provider:

```text
Codex CLI → OurCodex /proxy/v1/responses → selected upstream account
                                      ├─ OpenAI /v1/responses (API key)
                                      ├─ OpenAI /v1/responses (Sign in with ChatGPT)
                                      └─ ChatGPT Codex /responses (legacy auth.json)
```

The wrapper does not replace Codex or rewrite the user's permanent model-provider configuration. If the proxy is unreachable, it launches Codex with the user's normal local credentials.

OurCodex supports:

- browser-based Sign in with ChatGPT using OAuth Authorization Code + PKCE and a local loopback callback
- legacy ChatGPT OAuth credentials from `~/.codex/auth.json`, including refresh-token rotation and `ChatGPT-Account-ID`
- OpenAI API keys through the public Responses API
- account pools, model allowlists, per-user token quotas, budgets, and RPM limits
- Responses API streaming and usage accounting
- per-account Codex quota reads for both OAuth sign-in types, plus updates from `x-codex-*` response headers
- model aliases, optional instruction injection, response caching, webhooks, audit logs, and Prometheus metrics
- optional one-time pool resets at a chosen date and time, with a webhook reminder five hours before
- setup links, downloadable `ourcodex` binaries, owned-account sync, and MCP configuration sync

To schedule a pool reset, open its details in the dashboard and choose a local date and time under **Scheduled reset**. The schedule survives restarts and can be changed or cancelled. The reset reactivates exhausted accounts within one minute of the chosen time. Subscribe a webhook to `pool.reset.reminder` for the five-hour reminder; if the reset is sooner, the reminder is sent on the next scheduler check while it is still pending.

## Quick start

Requirements: Docker with Compose, and Codex CLI on each client machine.

```bash
cp .env.example .env
```

Set at least `JWT_SECRET` and `ADMIN_PASSWORD`, then start the service:

```bash
docker compose up --build -d
```

Open `http://localhost:3000`, sign in as the configured admin, then:

1. Create a pool.
2. Add an account to the pool.
3. Create a user and assign the pool.
4. Give the user their `sk-proxy-...` token or setup link.

On a client:

```bash
ourcodex login https://your-ourcodex.example sk-proxy-...
ourcodex
```

Install the official Codex CLI first, then download the matching `ourcodex`
binary from the dashboard's **Downloads** page:

```bash
curl -fsSL https://chatgpt.com/codex/install.sh | sh
chmod +x ./ourcodex
sudo mv ./ourcodex /usr/local/bin/ourcodex
```

An administrator can instead generate a user setup link, which provides a
one-command OurCodex installer with the proxy token already configured. With
**Sign in to Codex and share account** selected, the installer opens the
official Codex browser login, stores its credentials separately under
`~/.ourcodex/codex-login`, and imports the account into the proxy. The Codex
CLI must already be installed on that computer. The setup link grants access
to the user's proxy account, so share it only with that user.

Any normal Codex arguments can follow the wrapper name:

```bash
ourcodex "review this repository"
ourcodex exec "run the tests and fix failures"
```

## Adding accounts

### ChatGPT OAuth

In **Accounts**, choose **Add OAuth Account**, enter the account name and pool,
then generate the secure sign-in command. Run it on the computer where the
ChatGPT browser should open:

```bash
ourcodex account-login https://your-ourcodex.example oc-connect-...
```

The CLI uses a local `127.0.0.1` callback, PKCE, state and nonce validation, and
OpenAI's published signing keys. It transfers the verified tokens to OurCodex
over HTTPS using a one-time 15-minute pairing token. Access, refresh, and ID
tokens are encrypted at rest and are never stored in browser JavaScript.

Existing Codex `auth.json` credentials remain available as a legacy fallback.
An end user can also opt into sharing an existing local credential set during
setup:

```bash
ourcodex init https://your-ourcodex.example sk-proxy-...
```

Legacy OAuth credentials use the ChatGPT Codex backend and can be synchronized
back to their owning user. New Sign in with ChatGPT credentials use the public
Responses API and remain managed by OurCodex.

### OpenAI API key

Choose “API Key” when adding an account and paste an OpenAI API key. API-key and
Sign in with ChatGPT accounts are sent to `OPENAI_API_URL`; legacy OAuth
accounts are sent to `CHATGPT_CODEX_URL`.

### OpenAI quotas

The server attempts to read each OAuth account's Codex usage on startup, every
three minutes, and when an admin selects **Refresh quotas**. It uses that
account's stored OAuth credential; no model request is needed. The Quotas page
shows reported five-hour and weekly percentages, reset times, plan type, and
credit balance when available. A failed read is shown per account and keeps
its last successful snapshot. Sign in with ChatGPT tokens issued for the public
Responses API may be rejected by the ChatGPT quota endpoint. For those accounts,
import Codex CLI `auth.json` credentials in **Accounts → Add OAuth Account →
Legacy fallback** to allow quota reads.

API-key accounts use a different organization usage system and are not included
in these ChatGPT plan quota percentages.

### Account statuses

- `active`: eligible for pool selection.
- `disabled`: explicitly disabled by an administrator; upstream failures do not create this status.
- `exhausted`: temporarily rate-limited or out of the observed allowance.
- `error`: token refresh or a configured health check confirmed a credential problem.

## Build the client locally

```bash
make ourcodex
sudo make install-ourcodex
ourcodex login http://localhost:3000 sk-proxy-...
```

Build all supported client platforms with:

```bash
make ourcodex-all
```

## Manual Codex provider configuration

The wrapper supplies these settings only for the child Codex process. Other clients can configure the same provider themselves in `~/.codex/config.toml`:

```toml
model_provider = "ourcodex"

[model_providers.ourcodex]
name = "OurCodex"
base_url = "https://your-ourcodex.example/proxy/v1"
env_key = "OURCODEX_API_KEY"
wire_api = "responses"
requires_openai_auth = false
supports_websockets = false
```

Then set the user's proxy token before running Codex:

```bash
export OURCODEX_API_KEY=sk-proxy-...
codex
```

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `WEB_PORT` | `3000` | Dashboard and proxy HTTP port |
| `JWT_SECRET` | development fallback | Session signing secret; set in production |
| `ADMIN_USERNAME` | `admin` | Initial admin username |
| `ADMIN_PASSWORD` | empty | Initial admin password; required by Compose |
| `ENCRYPTION_KEY` | `JWT_SECRET` | OAuth token encryption key |
| `DB_TYPE` | `sqlite` | `sqlite` or `postgres` |
| `DB_PATH` | `/data/codex-proxy.db` | SQLite path |
| `POSTGRES_DSN` | empty | PostgreSQL connection string |
| `OPENAI_API_URL` | `https://api.openai.com/v1` | API-key upstream |
| `CHATGPT_CODEX_URL` | `https://chatgpt.com/backend-api/codex` | ChatGPT OAuth upstream |
| `OAUTH_REFRESH_URL` | `https://auth.openai.com/oauth/token` | Default OAuth refresh endpoint |
| `OAUTH_CLIENT_ID` | Codex client ID | OAuth client ID used for refresh |
| `POOL_RESET_INTERVAL_MINUTES` | disabled | Periodically reactivate exhausted accounts |
| `HEALTH_CHECK_INTERVAL_MINUTES` | disabled | Account health-check interval |
| `USER_MAX_RPM` | `0` | Per-user request limit; `0` is unlimited |
| `REDIS_URL` | empty | Optional shared rate-limit backend |
| `RESPONSE_CACHE_TTL_SECONDS` | `0` | Non-stream response cache; `0` disables it |
| `SYSTEM_PROMPT_INJECT` | empty | Text prepended to Responses `instructions` |
| `CORS_ORIGINS` | `*` | Allowed browser origins |

Runtime-editable values are also available on the Settings page.

## Security notes

- Put the service behind HTTPS before using it across a network.
- Use separate, strong values for `JWT_SECRET`, `ENCRYPTION_KEY`, and the admin password.
- Protect the database and backups: they contain encrypted credentials and operational metadata.
- Restrict dashboard access and rotate proxy tokens when a user leaves.
- Conversation logging can contain source code and prompts; set retention and access policies accordingly.
- The `ourcodex` wrapper uses `OURCODEX_API_KEY` for the proxy and does not expose the selected upstream credential to clients.

## Development

```bash
cd src/backend
go test ./...

cd ../frontend
npm ci
npm run build
```

No changes are committed automatically; inspect the working tree before creating a release.
