# Batch 5 ZTR — Zero-Touch Regression

Angular upload UI with a LangGraph workflow, Selenium browser smoke test, and OWASP ZAP security scanning.

## What the report means

The workflow performs two separate checks:

1. **Functional regression (Selenium):** extracts the uploaded ZIP, locates an `index.html`, serves the static files, opens the entry point in headless Chrome, and verifies that a usable page/body is rendered.
2. **Security scan (OWASP ZAP):** spiders the locally served static package and applies passive rules by default. Optionally, it can scan the live Juice Shop lab target; active scanning is opt-in and restricted to that local lab host.

The overall status is:

- **PASS:** functional check passed and no Medium/High ZAP alerts were found.
- **FAIL:** functional check failed, or one or more Medium/High ZAP alerts were found.
- **INCOMPLETE:** the security scanner could not complete; this is not treated as a clean security result.

Low and Informational alerts are listed in the report but do not fail the security gate. The alert list and risk counts are returned by the API.

**Important scope limitation:** a ZIP upload is served as static files. This does not start a project's backend, database, API, or server-side code. For a full Juice Shop lab test, start the `vulnerable-lab` Compose profile and enter `http://juice-shop:3000` in the live-target field. A PASS never proves that an application is vulnerability-free; it means only that this configured scan found no Medium/High alerts.

The current LangGraph stages are deterministic tool-driven checks; they do not call an LLM or use AI skills for code-impact reasoning.

## Safety limits

- ZIP upload limit: 200 MB.
- Maximum extracted content: 500 MB.
- Maximum ZIP entries: 20,000.
- Generated folders (`node_modules`, `dist`, `.angular`, `.git`, `__pycache__`) are skipped.
- ZAP passive scan is the default. Active scanning is opt-in and restricted to the configured Juice Shop lab on port 3000.
- Run intentionally vulnerable applications and scanners only in an isolated local lab. Do not expose them to the public internet.

## Prerequisites

- Docker Desktop with Docker Compose
- Internet access on first run to pull the Selenium Chrome and OWASP ZAP images

## Run with Docker (recommended)

From the extracted project root (the folder containing `docker-compose.yml`):

```powershell
docker compose up --build
```

Open http://localhost:4200. Upload a ZIP that contains an `index.html` and select **Run regression**. The first scan may take a few minutes while Selenium and ZAP start and the spider/passive scan completes. Leave the live target blank to scan the uploaded static package only.

### Test the live OWASP Juice Shop lab

Start the optional vulnerable target profile in a second terminal:

```powershell
docker compose --profile vulnerable-lab up --build
```

This starts Juice Shop at http://localhost:3000, bound to the local machine only. In the ZTR page, enter `http://juice-shop:3000` as the live target. Enable **active ZAP scan** only for this isolated Juice Shop lab. Active scanning sends test requests that may change application data; do not enable it for production or systems you do not own. The active scanner is restricted by the API to the local Juice Shop target on port 3000.

Services:

- Angular UI: http://localhost:4200
- Regression API: http://localhost:8100
- Selenium browser: http://localhost:4444
- Robot API: http://localhost:8001
- OWASP ZAP is available internally to the Compose network on port 8080; it is not published to the host.

Stop the stack with `Ctrl+C`, then run:

```powershell
docker compose down
```

## Local Gitea + Jenkins CI

The optional `ci` profile runs a local Gitea server and Jenkins controller. Both web interfaces are bound to loopback only:

- Gitea: http://localhost:3001
- Jenkins: http://localhost:8081

Create a local `.env` from `.env.example`, replace all placeholder secrets, then start the stack:

```powershell
Copy-Item .env.example .env
docker compose --profile ci up --build -d
```

Create the Gitea user and repository named by `GITEA_REPO_OWNER` and `GITEA_REPO_NAME` in `.env`, and make the repository public so the isolated Jenkins job can clone it without storing a second Git credential. Create a repository webhook:

- Target URL: `http://jenkins:8080/generic-webhook-trigger/invoke?token=<GITEA_WEBHOOK_TOKEN>`
- HTTP method: `POST`
- Content type: `application/json`
- Event: **Push**

Jenkins provisions the `ztr-ci` pipeline from the repository's `main` branch on startup. Pushes trigger a build that summarizes the commit range, checks Python syntax, builds Angular, builds and starts the regression services, and submits the built web package to the regression API for Selenium and ZAP analysis. The JSON report is archived as a Jenkins build artifact.

The Jenkins container mounts the Docker Engine socket so it can build and start the project's containers. Access to that socket is effectively host-level control; keep this stack local and do not expose Jenkins or Gitea to the internet. Gitea's webhook allowlist is limited to the `jenkins` Compose service. Use unique local secrets and do not commit `.env`.

## Local Angular development

The full regression flow requires the Docker services. To run only the Angular development server:

```powershell
cd apps\web
npm.cmd install
npm.cmd start
```

Open http://localhost:4200. The included `proxy.conf.json` forwards `/regress` to `http://localhost:8100`. Start the regression, Selenium, and ZAP services with Docker Compose in another terminal for the complete flow.

## API

`POST /regress` accepts either:

- a multipart ZIP file (`source_type=zip`), or
- a repository checkout / commit target (`source_type=repo` with `repo_path` and optional `commit_id`)

The JSON response includes `functionalStatus`, `securityStatus`, `securityCounts`, `securityAlerts`, `scanType`, and the overall `status`.

Jenkins is configured in `Jenkinsfile`; GitHub Actions is configured in `.github/workflows/ci.yml`.
