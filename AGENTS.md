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
