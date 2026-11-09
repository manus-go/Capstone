# CloudGuard SecOps & GitOps Automation Guidelines

## 1. Google Chat Notification Invariants
- **Card Exclusivity**: When sending interactive Card V2 messages via incoming webhooks, the JSON payload MUST contain only `"cardsV2"`. Never include a top-level `"text"` field alongside `"cardsV2"`, as Google Chat renders both, creating duplicate text bubbles.
- **Webhook Resilience**: Google Chat incoming webhooks may return transient 502/503 gateway errors. Always retry card delivery with exponential backoff (at least 2 attempts) before resorting to plain-text fallback.
- **No Raw Code in Chat**: User-facing cards and chat messages must describe remediation actions strategically and architecturally without exposing raw HCL or code blocks. Raw code belongs exclusively in Git branches and Pull Requests.
- **Markdown Formatting Divergence**: Never send raw CommonMark syntax into Google Chat:
  1. *Plain text notifications*: Use single-asterisk `*bold*`, unicode `• ` bullets, and `<url|text>` link syntax. Never use `**bold**` or `*   ` list indentation.
  2. *Card V2 textParagraph widgets*: Use supported subset HTML (`<b>bold</b>`, `<i>italic</i>`, `<a href="...">text</a>`, and `• ` with `<br>` line breaks).
  3. *Deterministic Sanitization*: All automated messages and card paragraphs must pass through dedicated sanitizers (`format_google_chat_markdown` and `format_chat_card_html`) prior to dispatch to prevent raw asterisks from rendering.
- **Minimalistic PR Confirmation Card (No External Logos)**: PR staging confirmations must use a clean, distraction-free Card V2 layout featuring key-value summary attributes, an interactive "Review PR #{pr_number} on GitHub →" text button, and a safety status badge. Do NOT include third-party logo images (specifically NO GitHub Octocat logo).
- **Deep Dive Channel Separation**: When an operator clicks "Show More Details", the service must render exclusively the browser deep-dive inspection webpage. Redundant follow-up companion cards or notification bubbles in Google Chat must be completely suppressed.
- **Progressive Disclosure in Chat**: The primary alert card must be scannable in 5 seconds (Severity, Category, parsed clean resource name, 1-sentence issue & risk summary, and 1-line Option summaries with `⭐ AI Recommended` on the preferred strategy). Detailed architectural justifications must be deferred to an in-chat follow-up Card V2 utilizing native collapsible sections (`collapsible: true`, `uncollapsibleWidgetsCount: 1`) or an interactive deep-dive inspector callback.
- **Direct SCC Console Deep Link**: All finding alert cards must provide a direct URL link to the SCC Console findings dashboard (`https://console.cloud.google.com/security/command-center/findings?project={project_id}`).

## 2. Infrastructure as Code (IaC) & Remediation Policy
- **Strictly Terraform**: All automated and suggested remediation options must be declarative Terraform (HCL) changes (e.g., resource arguments, IAM member bindings, encryption settings). Never suggest or generate Google Cloud Console steps or imperative `gcloud` CLI commands.
- **Human-in-the-Loop GitOps**: Remediation code must NEVER be applied directly to cloud environments. Always stage code onto a dedicated branch and open a GitHub Pull Request for engineer review and approval.
- **In-Place Baseline Modifications for True Git Diffs**: For realistic GitOps evaluations and demos, remediation agents should modify pre-existing baseline infrastructure files (e.g., `infrastructure/main.tf`) in the GitHub repository rather than exclusively committing new isolated files.
- **GitHub Contents API Blob SHA Invariant**: When committing updates to an existing file in GitHub via `PUT /repos/{owner}/{repo}/contents/{path}`, the API requires passing the file's current commit blob `sha`. Omitting the blob SHA returns HTTP 422 Unprocessable Entity. The agent must first query `GET /repos/{owner}/{repo}/contents/{path}?ref={base_branch}` to extract the SHA prior to staging commits.
- **Streamlined 4-Part Pull Request Format**: All automated GitHub Pull Request bodies must follow a direct, non-conversational 4-part structure:
  1. **What is causing the issue**: 1-2 sentence concise summary of the misconfiguration.
  2. **The Error / Risk**: Resource affected and security impact.
  3. **Recommended Fix Applied**: Specific strategy and target file path.
  4. **Call to Action**: Exactly: *"Please check the files changed in this PR, review the Terraform diff, and merge/apply to handle this."*
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
- **Solving Orb Canvas Engine & SSE Streaming**: Staging screens and agent cognitive wait states must render the 2D canvas **Solving Orb** particle field configured with CloudGuard's palette:
  - *Orbital trails*: Electric Blue (`#38bdf8` / `rgba(56, 189, 248, 0.85)`)
  - *Harmonic core*: Emerald Green (`#10b981` / `rgba(16, 185, 129, 0.90)`)
  - *Ambient glow*: Dark Slate / Indigo (`rgba(14, 165, 233, 0.15)`)
- **Server-Sent Events (SSE) Progress**: Multi-step remediation pipelines must stream milestone events (`text/event-stream`) to dynamically update orb status text and pipeline step indicators without page reloads.
- **Concurrent Post-PR I/O**: After opening a GitHub PR, non-dependent persistence (Firestore audit) and external notifications (Google Chat) must execute concurrently via a thread pool to minimize operator wait time.
- **Client-Side Background Execution**: The loading UI must trigger the actual agent execution via asynchronous background `fetch(...?action=execute)` while rendering an animated progress bar and pipeline step checklist.
- **Review Dashboard Completeness**: Upon completion, the UI must display the GitHub PR link, committed branch, target file, architectural rationale, and a read-only HCL code viewer tagged with `Safely Staged • NOT Applied`.
- **Progressive Disclosure via Accordions**: Completed remediation screens must eliminate walls of text. Heavy technical details must be organized into clean collapsible `<details class="accordion">` components:
  1. 💡 *Architectural Reasoning & Trade-Offs*
  2. 🛡️ *Compliance & Workload Blast Radius Analysis*
  3. 📦 *Staged Terraform HCL Preview* (badged `Safely Staged • NOT Applied`)

## 7. Autonomous ADK Multi-Tool GitOps Execution Order
- **Sequential Tool Chain**: Autonomous ADK remediation agents must enforce a strict 6-step operational pipeline:
  1. Fetch existing baseline Terraform code and commit blob SHA from GitHub (`infrastructure/main.tf`).
  2. Generate complete declarative Terraform code refactoring the baseline in-place with inline remediation comments.
  3. Invoke `validate_terraform_code` to verify syntax, required HCL blocks, and brace matching.
  4. Invoke `create_github_pull_request_tool` specifying `existing_file_sha` to stage a true red/green diff on a dedicated branch.
  5. Invoke `record_remediation_audit` to persist audit records in `alerts/` and `remediations/`.
  6. Invoke `dispatch_google_chat_notification` to broadcast PR details without raw code to Google Chat.
- **Pre-Execution Idempotency Gate**: Webhook handlers must check `alert_data["remediation_status"] == "PR_OPENED"` and `existing_pr_url` prior to initializing the ADK runner, immediately returning the existing PR to avoid duplicate branches, commits, or notifications.

## 8. Security Finding Simulation & Test Harness Invariants
- **Automated Teardown Required**: Any script creating intentionally vulnerable cloud infrastructure (e.g., public storage buckets, broad firewall rules, over-privileged IAM bindings) MUST implement a corresponding `--delete` / cleanup flag to remove resources immediately after test completion.
- **REST/ADC Portability**: Simulation scripts must offer zero-dependency Python implementations utilizing Google Cloud REST APIs and Application Default Credentials (`~/.config/gcloud/application_default_credentials.json` or `google-auth`), alongside optional shell/CLI (`gcloud`) scripts.
- **Dual-Mode Simulation & CAI Latency Awareness**:
  1. *Physical Infrastructure Mode*: Simulates real misconfigured cloud assets (e.g. buckets with public ACLs). Documentation must explicitly note the Cloud Asset Inventory (CAI) mixed-mode scanning model, where Security Health Analytics (SHA) batch scanning cycles introduce a 10–30+ minute detection lag.
  2. *Instant Custom Source Mode (Organization-Level)*: In GCP environments with an active Organization node, simulation scripts support direct event injection into an Organization-level Custom Finding Source (`organizations/{org_id}/sources/{source_id}`) with `state="ACTIVE"`, rendering the finding directly in the SCC Console and streaming through Continuous Export.
- **Standalone Project Simulation (Direct Pub/Sub Injection)**: In standalone GCP projects lacking an Organization node (`organization_id = ""`), the Security Command Center v1 REST API rejects custom source creation (`/v1/projects/{project_id}/sources` returns HTTP 404). In standalone environments, simulation scripts must support direct event publication to the project's Continuous Export Pub/Sub topic (`scc-high-alerts-topic`), ensuring instant pipeline triggering without CAI batch scan latency.
- **Continuous Export Pub/Sub Schema Fidelity**: Direct Pub/Sub event injection must conform to the nested SCC Continuous Export envelope schema (base64-encoded `finding` and `resource` dictionaries with `eventTime`, `createTime`, `state="ACTIVE"`, and attributes `finding_id`, `category`, `severity`) to ensure transparent processing by downstream `scc-alert-router` EventArc triggers.
- **Dual-Path Finding Lifecycle & Dashboard Hygiene**: Finding simulation tools must provide automated lifecycle controls (`--mute` and `--inactive`):
  1. *Organization Mode*: Call SCC v1 `:setMute` (`POST /v1/{name}:setMute` with `mute="MUTED"`) to clear resolved alerts from active SCC console dashboards.
  2. *Standalone Mode*: Update the corresponding Firestore document (`alerts/{finding_id}`) via REST API with `remediation_status="DISMISSED_NO_ACTION"` and `action_taken="MUTED_VIA_SIMULATOR"` to prevent ghost alerts and maintain accurate MTTR metrics on the SecOps Command Dashboard.
- **Detector Semantics & Documentation**: Each simulation toolchain must be documented in `scripts/README.md` defining:
  1. The exact SCC detector ID and trigger conditions (e.g. UBLA disabled, PAP inherited).
  2. Public principal semantics (distinguishing unauthenticated internet `allUsers` from authenticated accounts `allAuthenticatedUsers`).
  3. Declarative Terraform (HCL) remediation snippet adhering to Section 2.

## 9. Hybrid Telemetry & SecOps Command Dashboard Invariants
- **Domain-Specific KPI Data Sourcing**: SecOps dashboards must partition metrics by their native operational strengths:
  1. **Immutable Ingestion Telemetry (BigQuery)**: BigQuery (`secops_lake.scc_findings_raw`) is the authoritative source for total ingested event volume, long-term multi-day telemetry, and raw finding distribution by severity.
  2. **Real-Time Lifecycle State (Cloud Firestore)**: Firestore (`alerts` and `remediations`) is the authoritative source for low-latency point lookups, operational workflow states (`NOTIFIED`, `PR_OPENED`, `DISMISSED_NO_ACTION`), and Mean Time to Remediation (MTTR) tracking.
- **4-Stage Lifecycle Audit Trail**: Finding audit records must track and display 4 sequential lifecycle stages with exact UTC timestamps:
  1. *SCC Ingestion & Event Detection*
  2. *Gemini Vertex AI Triage & Google Chat Dispatch*
  3. *Operator Decision & Action Chosen*
  4. *Autonomous ADK GitOps Execution & PR Creation*
- **DOM Entity Hygiene**: Dynamic JavaScript DOM updates must never inject raw HTML character entities (such as `&rarr;`) through `.innerText` or `.textContent`. Always use literal unicode glyphs (`→`) or assign via `.innerHTML`.
- **Fixed-Grid Actions Column Alignment**: Table actions containing conditional elements (e.g., `Review PR` and `📋 Audit Trail`) must enforce a fixed-column layout (such as a 2-column CSS Grid `140px 120px` with fixed slot widths). Even when findings do not have an open PR, slot 1 must maintain its width so that all `📋 Audit Trail` buttons in slot 2 remain strictly vertically aligned across all table rows.
