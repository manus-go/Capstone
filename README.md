# CloudGuard: AI-Powered SecOps & GitOps Automation Pipeline

CloudGuard is an automated SecOps and GitOps remediation platform on Google Cloud. It streams Security Command Center (SCC) findings into Pub/Sub, triages alerts using autonomous Gemini agents, notifies security teams via Google Chat Card V2, and automates declarative Terraform remediations via GitHub Pull Requests.

---

## Architecture Overview

```
+------------------------------------+
|  Google Cloud Security Command     |
|  Center (Continuous Export)        |
+-----------------+------------------+
                  | Filter: ACTIVE & (HIGH | CRITICAL)
                  v
+-----------------+------------------+
|  Pub/Sub Topic                     |
|  (scc-high-alerts-topic)           |
+--------+-----------------+---------+
         |                 |         |
         v                 v         v
+--------+-------+  +------+------+  +-------------------------------------+
| Pull           |  | BigQuery    |  | Cloud Function (Gen 2)             |
| Subscription   |  | Ingestion   |  | (scc-alert-router)                 |
| (test payload) |  | Table       |  +------------------+------------------+
+----------------+  +-------------+                     |
                                                        v
                                         +--------------+------------------+
                                         | Cloud Firestore Database        |
                                         | - alerts (triage & fix options) |
                                         | - issue_preferences             |
                                         +--------------+------------------+
                                                        |
                                                        v
                                         +--------------+------------------+
                                         | Google Chat Space               |
                                         | Interactive Card V2 Alerts      |
                                         +--------------+------------------+
                                                        | Click "Code Fix"
                                                        v
                                         +--------------+------------------+
                                         | Cloud Run Receiver              |
                                         | (scc-remediation-receiver)      |
                                         +--------------+------------------+
                                                        |
                                                        v
                                         +--------------+------------------+
                                         | GitHub Pull Request             |
                                         | Declarative Terraform (HCL)     |
                                         +---------------------------------+
```

---

## Repository Structure

- [`terraform-foundation/`](./terraform-foundation/): Terraform HCL configs for SCC export, Pub/Sub, BigQuery lake, Firestore, Cloud Functions, and Cloud Run receivers. See [Terraform README](./terraform-foundation/README.md).
- [`functions/`](./functions/):
  - `scc-alert-router`: Cloud Function evaluating alerts, invoking the Gemini Triage Agent, and posting Google Chat cards.
  - `scc-remediation-receiver`: Cloud Run service running the Gemini Remediation Agent to generate declarative Terraform fixes and open GitHub PRs.
- [`scripts/`](./scripts/): Finding generation and test scripts (including Public Bucket ACL simulation). See [Scripts README](./scripts/README.md).
- [`tests/`](./tests/): End-to-end integration and interactive test runners (`e2e_test.py`, `interactive_session.py`).
- [`AGENTS.md`](./AGENTS.md): Workspace policies and invariants for autonomous ADK agents, Google Chat payloads, and GitOps standards.

---

## Security Finding Simulation & Testing

To simulate findings and verify the end-to-end alert-to-PR workflow, see the [`scripts/` documentation](./scripts/README.md):

- **Trigger Public Bucket ACL (`PUBLIC_BUCKET_ACL`)**:
  ```bash
  python3 scripts/create_public_bucket.py
  ```
  *(See [`scripts/README.md`](./scripts/README.md) for custom parameters, shell alternatives, and cleanup commands).*
