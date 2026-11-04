# CloudGuard SecOps & GitOps Automation Guidelines

## 1. Google Chat Notification Invariants
- **Card Exclusivity**: When sending interactive Card V2 messages via incoming webhooks, the JSON payload MUST contain only `"cardsV2"`. Never include a top-level `"text"` field alongside `"cardsV2"`, as Google Chat renders both, creating duplicate text bubbles.
- **Webhook Resilience**: Google Chat incoming webhooks may return transient 502/503 gateway errors. Always retry card delivery with exponential backoff (at least 2 attempts) before resorting to plain-text fallback.
- **No Raw Code in Chat**: User-facing cards and chat messages must describe remediation actions strategically and architecturally without exposing raw HCL or code blocks. Raw code belongs exclusively in Git branches and Pull Requests.

## 2. Infrastructure as Code (IaC) & Remediation Policy
- **Strictly Terraform**: All automated and suggested remediation options must be declarative Terraform (HCL) changes (e.g., resource arguments, IAM member bindings, encryption settings). Never suggest or generate Google Cloud Console steps or imperative `gcloud` CLI commands.
- **Human-in-the-Loop GitOps**: Remediation code must NEVER be applied directly to cloud environments. Always stage code onto a dedicated branch and open a GitHub Pull Request for engineer review and approval.
- **Idempotency**: All webhook receivers and remediation executors must verify whether a finding has already been remediated or has an active PR before creating duplicate branches, PRs, or notifications.

## 3. Google Agent Development Kit (ADK) Guidelines
- **Framework Standard**: Use `google-adk` (`google.adk.agents.Agent`, `Runner`, `InMemorySessionService`) with `GOOGLE_GENAI_USE_VERTEXAI = "TRUE"`. Always provide an explicit `app_name` to `Runner`.
- **Zero-Fallback Policy**: Never implement synthetic mock fallbacks, hardcoded HCL templates, or fallback dictionaries. Let the model reason and call tools. If a failure occurs, report the real exception.
- **Tool Definitions**: All ADK tool functions must have strict Python type annotations and Google/Sphinx style `Args:` docstrings so ADK can generate valid OpenAPI function declarations for Gemini.

## 4. Cloud Functions Gen 2 & Cloud Run Invariants
- **CPU & Memory Ratios**: When configuring Cloud Functions Gen 2 / Cloud Run containers with `available_memory = "1024M"` or higher, ALWAYS set `available_cpu = "1"` in Terraform `service_config`. Omitting CPU triggers Cloud Run deployment validation errors.

## 5. Technical Documentation & Google Docs Invariants
- **Non-Destructive Section Updates**: When updating existing Google Docs or architecture specifications, never use full-document wipes (`mutate write` or full `mutate sync`) if the document contains embedded diagrams, images, or drawings. Always map character index boundaries (`readonly structure --json`) and perform targeted in-place section updates.
- **Paragraph Style Isolation**: When inserting rich-text runs or body paragraphs after headings in batch operations, explicitly enforce `namedStyleType: "NORMAL_TEXT"` to prevent paragraphs from inheriting heading styles.
- **Ephemeral Validation for Complex Batches**: For batch updates containing tables or dense formatting, always validate the batch execution against an ephemeral scratch document before modifying live design documents.

## 6. Two-Phase Browser Webhook & Staging UI Invariants
- **Sub-50ms Initial Response**: When an operator navigates to or clicks a Cloud Run webhook receiver from a browser (`GET` with `text/html` accept header), the service must immediately return a lightweight interactive loading page (`< 50ms`) rather than blocking the HTTP connection during agent reasoning.
- **Client-Side Background Execution**: The loading UI must trigger the actual agent execution via asynchronous background `fetch(...?action=execute)` while rendering an animated progress bar and pipeline step checklist.
- **Review Dashboard Completeness**: Upon completion, the UI must display the GitHub PR link, committed branch, target file, architectural rationale, and a read-only HCL code viewer tagged with `Safely Staged • NOT Applied`.

## 7. Autonomous ADK Multi-Tool GitOps Execution Order
- **Sequential Tool Chain**: Autonomous ADK remediation agents must enforce a strict 5-step operational pipeline:
  1. Generate complete declarative Terraform code with inline remediation comments.
  2. Invoke `validate_terraform_code` to verify syntax, required HCL blocks, and brace matching.
  3. Invoke `create_github_pull_request_tool` to create a dedicated branch, commit HCL, and open a PR.
  4. Invoke `record_remediation_audit` to persist audit records in `alerts/` and `remediations/`.
  5. Invoke `dispatch_google_chat_notification` to broadcast PR details without raw code to Google Chat.
- **Pre-Execution Idempotency Gate**: Webhook handlers must check `alert_data["remediation_status"] == "PR_OPENED"` and `existing_pr_url` prior to initializing the ADK runner, immediately returning the existing PR to avoid duplicate branches, commits, or notifications.

## 8. Security Finding Simulation & Test Harness Invariants
- **Automated Teardown Required**: Any script creating intentionally vulnerable cloud infrastructure (e.g., public storage buckets, broad firewall rules, over-privileged IAM bindings) MUST implement a corresponding `--delete` / cleanup flag to remove resources immediately after test completion.
- **REST/ADC Portability**: Simulation scripts must offer zero-dependency Python implementations utilizing Google Cloud REST APIs and Application Default Credentials (`~/.config/gcloud/application_default_credentials.json` or `google-auth`), alongside optional shell/CLI (`gcloud`) scripts.
- **Dual-Mode Simulation & CAI Latency Awareness**:
  1. *Physical Infrastructure Mode*: Simulates real misconfigured cloud assets (e.g. buckets with public ACLs). Documentation must explicitly note the Cloud Asset Inventory (CAI) mixed-mode scanning model, where Security Health Analytics (SHA) batch scanning cycles introduce a 10–30+ minute detection lag.
  2. *Instant Custom Source Mode*: For live demonstrations, evaluator walkthroughs, or fast CI test suites requiring deterministic sub-second triggers, simulation scripts must support direct event injection into a project-level Custom Finding Source (`projects/{project_id}/sources/{source_id}`) with `state="ACTIVE"`, bypassing CAI scan latency and immediately triggering Continuous Export Pub/Sub pipelines.
- **Finding Lifecycle & Dashboard Hygiene**: Finding simulation tools must provide automated lifecycle controls (`--mute` via `set-mute` / `POST :setMute` with `mute="MUTED"`, or `--inactive`) to clear resolved alerts from active SCC console dashboards without leaving lingering security noise.
- **Detector Semantics & Documentation**: Each simulation toolchain must be documented in `scripts/README.md` defining:
  1. The exact SCC detector ID and trigger conditions (e.g. UBLA disabled, PAP inherited).
  2. Public principal semantics (distinguishing unauthenticated internet `allUsers` from authenticated accounts `allAuthenticatedUsers`).
  3. Declarative Terraform (HCL) remediation snippet adhering to Section 2.

