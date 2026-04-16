# Zenvra Configuration & Hardcoded Values

## Current State

### ✅ Already Configurable via Environment Variables

1. **Backend API URL** — `PUBLIC_API_URL` (default: `http://localhost:8080`)
   - Used in: `apps/web/src/lib/api.ts`, `apps/web/src/lib/stores/aiConfig.svelte.ts`
   - Allows pointing to different API endpoints (local dev, staging, production)

2. **AI Provider Configuration** — Persisted in localStorage
   - **Provider**: anthropic, openai, google, custom (user-selected)
   - **API Key**: User-provided via Settings UI
   - **Model**: User-selected from available models for provider
   - **Endpoint**: Optional, user-provided for custom providers
   - Allows bring-your-own-key pattern ✓

3. **Database URL** — `DATABASE_URL` in `.env` (for server)
   - Allows local dev, Docker, or cloud databases

4. **CVE Data Feeds** — `NVD_API_KEY` in `.env`
   - Synced on server startup or manual trigger

### ⚠️ Hardcoded Values to Consider

1. **Server Port** — `8080` (hardcoded in server)
   - Suggestion: Make configurable via `PORT` env var

2. **Web Dev Port** — `5173` (Vite default)
   - Vite automatically uses next available port if occupied

3. **Database Credentials** — `postgres:postgres@localhost:5433/zenvra`
   - Should be parameterized in `.env`

4. **Scan Engines** — Hardcoded in CLI/server (sast, sca, secrets, ai_code)
   - Already configurable per-request via `--disable` flag and API

5. **Severity Thresholds** — Default `low` in CLI
   - Already configurable via `--severity` flag

### 📋 Recommended Next Steps

1. **Server** — Add `PORT` and `HOST` env vars
2. **Web** — Consider `PUBLIC_APP_NAME`, `PUBLIC_VERSION` for UI
3. **Database** — Already parametrized in `.env`
4. **AI Config** — Already per-user via localStorage + Settings UI

## How to Use Development Environment

```bash
# Terminal 1: Start PostgreSQL + Redis
docker compose up -d postgres redis

# Terminal 2: Start API Server
set -a && source .env && set +a
cargo run -p zenvra-server

# Terminal 3: Sync CVE data
cargo run -p zenvra-server -- sync

# Terminal 4: Start Web Frontend
cd apps/web
pnpm dev

# Open http://localhost:5174 in browser
```

## API Endpoints

- `/health` — Health check
- `/api/v1/scan` — Submit code scan (returns scan ID)
- `/api/v1/scan/:id/events` — Stream scan results via SSE
- `/api/v1/history` — Get scan history
- `/api/v1/sync` — Trigger manual CVE sync
- `/api/v1/ai/models` — Fetch available AI models for provider
