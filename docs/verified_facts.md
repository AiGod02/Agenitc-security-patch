# Verified Facts (`docs/verified_facts.md`)

All facts in this file were verified empirically via live API calls and local host/container commands on **2026-10-29**. No API secrets are recorded here.

---

## 1. Meta Model API (`https://api.meta.ai/v1`) — Verified 2026-10-29

### 1.1 Model List (`GET https://api.meta.ai/v1/models`)
- **Verified Date**: `2026-10-29T05:11:40Z` (`x-request-id: 9f1a8e3c-2af0-468b-ac3b-852ba228f73d`)
- **HTTP Status**: `200 OK`
- **Returned Model IDs (`owned_by: "meta"`)**:
  - `muse-spark-1.3` — **Selected for `fast` role**
  - `muse-wonder-1.0` — **Selected for `reasoning` role**
  - `muse-spark-1.3-contributor` (lower rate limit: 150 requests/window)
  - `muse-spark-1.2`
  - `muse-spark-1.2-contributor`
  - `muse-spark-1.1`
  - `muse-image-1.0` (image generation on `/v1/responses` only)
  - `sam-3.1` (vision/video input required on `/v1/responses` only)
  - `muse-voice-transcribe-1.0` (`404 model_not_found` on text `/responses` and `/chat/completions`)

### 1.2 Endpoints, Rate Limits, and Reasoning Defaults
Both `/v1/responses` and `/v1/chat/completions` returned `200 OK` for `muse-spark-1.3` and `muse-wonder-1.0`. We standardize on **`POST https://api.meta.ai/v1/responses`** because it natively supports `instructions`, `reasoning.effort`, strict `text.format` (`json_schema`), function calling, and full reasoning/cached token telemetry.

| Model ID | Role | Default `reasoning.effort` | Rate Limit (Requests) | Rate Limit (Tokens) | Smoke Request ID (`/v1/responses`) |
|---|---|---|---|---|---|
| `muse-spark-1.3` | `fast` | `"high"` (also supports `"low"`, verified `200 OK`) | `3000` (`x-ratelimit-limit-requests`) | `4000000` (`x-ratelimit-limit-tokens`) | `e8f33741-affa-482c-986e-92d19f613270` |
| `muse-wonder-1.0` | `reasoning` | `"max"` | `3000` (`x-ratelimit-limit-requests`) | `4000000` (`x-ratelimit-limit-tokens`) | `a61bd3cd-0411-415c-a87e-391065fd9ddc` |

### 1.3 Verified Request & Response Shapes (`POST /v1/responses`)

**Structured JSON Output (`200 OK` verified on both `muse-wonder-1.0` [`410be71e-604a-4717-84fe-33e4102919f7`] and `muse-spark-1.3` [`6a38539c-77a5-4d74-bfbc-7f878af96389`])**:
- Request payload fields:
  ```json
  {
    "model": "muse-spark-1.3",
    "instructions": "<system prompt>",
    "input": "<user prompt>",
    "reasoning": {"effort": "low"},
    "text": {
      "format": {
        "type": "json_schema",
        "name": "<schema_name>",
        "strict": true,
        "schema": {
          "type": "object",
          "properties": {"...": "..."},
          "required": ["..."],
          "additionalProperties": false
        }
      }
    }
  }
  ```
  *(Note: OpenAI/Meta strict JSON schema requires `"additionalProperties": false` and all properties listed in `"required"` on every object node.)*
- Response output extraction:
  - `body["status"] == "completed"`
  - `body["output"]` is an array containing items with `"type": "reasoning"` and `"type": "message"`.
  - Assistant text is in `item["content"][i]["text"]` where `item["type"] == "message"` and `content[i]["type"] == "output_text"`.
- Verified `usage` object in `/v1/responses`:
  ```json
  {
    "input_tokens": 76,
    "input_tokens_details": {"cached_tokens": 0},
    "output_tokens": 218,
    "output_tokens_details": {"reasoning_tokens": 198},
    "total_tokens": 294
  }
  ```
- Function calling (`200 OK` verified on `muse-wonder-1.0` [`0e5c6d9a-d687-4219-a027-65b5eb3cddc2`] and `muse-spark-1.3` [`49a56d8a-edaa-4254-944b-8283d6acb67e`]):
  - Emits output item `{"type": "function_call", "call_id": "...", "name": "...", "arguments": "{...}", "status": "completed"}` alongside prompt cache hits in `usage.input_tokens_details.cached_tokens`.

---

## 2. Local Toolchain & Sandbox Runtime — Verified 2026-10-29

- **OS**: Windows (AMD64) with WSL2 Linux container backend
- **Python**: `3.11.5` (`pip 23.2.1`)
- **Verified Installed Python Packages (pinned in `pyproject.toml`)**:
  - `pydantic==2.7.4`
  - `httpx==0.27.2`
  - `fastapi==0.115.0`
  - `uvicorn==0.30.6`
  - `pytest==8.3.2`
- **Node.js / npm**: `v18.18.0` / `9.8.1`
- **Git**: `git version 2.42.0.windows.2`
- **Docker**: `Docker version 25.0.2, build 29cf629`, server `25.0.2 | linux` (verified live).
  - Exact container flags and egress/write-escape/timeout proof outputs are recorded in Section 4 below.

---

## 3. Explicitly Unverified Items (`UNVERIFIED:`)

Per Section 1.3 Rule 4 and Section 9:
- **`UNVERIFIED:` Meta API per-token USD pricing**: The `/v1/models` and `/v1/responses` payloads report exact token counts (`input_tokens`, `cached_tokens`, `output_tokens`, `reasoning_tokens`, `total_tokens`) and rate-limit headers, but do not include dollar pricing. Per Section 9 ("Compute cost only from verified pricing; otherwise record `'unknown'`. Never estimate silently"), the cost logger records `"cost_usd": "unknown"` alongside exact provider-reported token counts.
- **`UNVERIFIED:` Official hackathon track/language fine print**: Public listing shows deadline 5 Nov 2026 6:30 AM IST (internal cutoff 4 Nov 2026 6:00 PM IST); confirm Python orchestrator + Node/Express target eligibility with organizers if required by private portal rules.

---

## 4. Verified Docker Sandbox Command & Isolation Proofs — Verified 2026-10-29

### 4.1 Image Build Command
```bash
docker build -t psa-sandbox:latest -f docker/Dockerfile .
```
- Base image: `node:18-bookworm-slim` (`sha256:f9ab18e354e6855ae56ef2b290dd225c1e51a564f87584b9bd21dd651838830e`)
- Built image digest: `sha256:e510e0c281f3f58c2dd802623c733d678d2e00a643e35a594201f1be6fc35bc0`
- Pre-baked dependencies in `/opt/psa-deps/node_modules` (`NODE_PATH=/opt/psa-deps/node_modules`, `PATH=/opt/psa-deps/node_modules/.bin:...`), so `--network none` containers never run `npm install`.

### 4.2 Exact Verified Container Invocation (`agent/sandbox/runner.py`)
```bash
docker run --rm --name psa-<agent_tag>-<hex10> \
  --network none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=64m \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --pids-limit 128 \
  --memory 512m \
  --cpus 1.0 \
  --user 1000:1000 \
  -e AUTH_TOKEN_SECRET=sandbox-ephemeral-test-secret \
  -e WEBHOOK_API_KEY=sandbox-ephemeral-webhook-key \
  -e ALLOWED_ORIGIN=https://app.internal.example \
  -v <disposable_workspace_abs_path>:/workspace:rw \
  -w /workspace \
  psa-sandbox:latest <command...>
```

### 4.3 Empirical Isolation Proof Outputs
1. **No Network Egress (`node egress_probe.js` attempting `fetch('https://1.1.1.1')`)**:
   - Observed result: `exit_code=42`, `timed_out=False`, `duration_ms=4643`, `stderr='EGRESS_BLOCKED:ENETUNREACH'`
2. **No Write Outside Workspace (`node write_probe.js` attempting `fs.writeFileSync('/etc/escape_probe', 'x')`)**:
   - Observed result: `exit_code=43`, `timed_out=False`, `duration_ms=2205`, `stderr='WRITE_BLOCKED:EROFS'`
3. **Hard Wall-Clock Timeout Kill (`node hang.js` with `timeout_s=3.0`)**:
   - Observed result: `exit_code=124`, `timed_out=True`, `duration_ms=3526` (container forcefully removed via `docker rm -f`)
4. **Fixture Baseline Jest Suite Inside Container (`jest --runInBand --json`)**:
   - Observed result: `exit_code=0`, `numPassedTests=6`, `numFailedTests=0` (`tests/test_sandbox_s2.py`: `4 passed in 15.89s`)
