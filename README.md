# OurCodex

OurCodex is a self-hosted Codex Responses API proxy with account pools, per-user access tokens, usage controls, and an admin dashboard. Users run the `ourcodex` wrapper, while the server selects an eligible ChatGPT OAuth account or OpenAI API key from their assigned pools.

> [!IMPORTANT]
> This project handles sensitive OpenAI credentials. Review OpenAI's current terms and your organization's policies before pooling or sharing subscription accounts. API keys are the clearest option for organizational usage. You are responsible for securing the deployment and using accounts within their applicable terms.

## How it works

The `ourcodex` command launches the installed `codex` CLI with a temporary custom model provider:

```text
Codex CLI → OurCodex /proxy/v1/responses → selected upstream account
                                      ├─ OpenAI /v1/responses (API key)
                                      └─ ChatGPT Codex /responses (OAuth)
```

The wrapper does not replace Codex or rewrite the user's permanent model-provider configuration. If the proxy is unreachable, it launches Codex with the user's normal local credentials.

OurCodex supports:

- ChatGPT OAuth credentials from `~/.codex/auth.json`, including refresh-token rotation and `ChatGPT-Account-ID`
- OpenAI API keys through the public Responses API
- account pools, model allowlists, per-user token quotas, budgets, and RPM limits
- Responses API streaming and usage accounting
- Codex primary/secondary rate-limit snapshots from real `x-codex-*` response headers
- model aliases, optional instruction injection, response caching, webhooks, audit logs, and Prometheus metrics
- setup links, downloadable `ourcodex` binaries, owned-account sync, and MCP configuration sync

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

Any normal Codex arguments can follow the wrapper name:

```bash
ourcodex "review this repository"
ourcodex exec "run the tests and fix failures"
```

## Adding accounts

### ChatGPT OAuth

Log into Codex on the account owner's machine:

```bash
codex login
```

In the dashboard, add an OAuth account and paste the complete contents of `~/.codex/auth.json`. Alternatively, an end user can opt into sharing their local credential set during setup:

```bash
ourcodex init https://your-ourcodex.example sk-proxy-...
```

OAuth credentials are encrypted at rest. The proxy refreshes expiring access tokens and exports refreshed credentials to the owning user so their local Codex session can stay in sync.

### OpenAI API key

Choose “API Key” when adding an account and paste an OpenAI API key. API-key accounts are sent to `OPENAI_API_URL`; OAuth accounts are sent to `CHATGPT_CODEX_URL`.

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
