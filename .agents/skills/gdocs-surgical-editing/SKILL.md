---
name: gdocs-surgical-editing
description: Surgical in-place section editing for Google Docs with embedded images, diagrams, and rich formatting. Use when updating specific sections of an existing Google Doc without disturbing adjacent headings, diagrams, or images.
---

# Google Docs Surgical In-Place Editing Workflow

Use this workflow whenever updating specific sections in existing Google Docs (design documents, architecture specs, project proposals) that contain embedded images, diagrams, or drawings.

## Core Rules & Invariants
1. **Never Wipe or Sync Whole Docs**: Never use `gdocs mutate write` or full `gdocs mutate sync` on docs containing diagrams or images. Full document rewrites strip or corrupt inline media and drawings.
2. **Always Use Network Sandbox Bypass for Google APIs**: `gdocs` operations interact with Google Docs and Drive APIs, requiring `BypassSandbox: true` on network calls.
3. **Paragraph Style Isolation**: When appending rich-text runs or paragraphs after headings, always ensure `namedStyleType` is explicitly set to `NORMAL_TEXT` (via `raw` requests or `format-paragraph`), avoiding unintentional heading level inheritance.

---

## 4-Step Surgical Update Procedure

### Step 1: Discover Character Index Boundaries
Export document structure to JSON:
```bash
gdocs readonly structure DOC_ID --json > /tmp/doc_structure.json
```
Use a script to inspect elements and identify the exact `start_index` and `end_index` of the section to replace:
```python
import json
with open("/tmp/doc_structure.json") as f:
    elements = json.load(f)

for p in elements:
    if "Target Section Heading" in p.get("text", ""):
        print("Start:", p["start_index"], "End:", p["end_index"])
```

### Step 2: Prepare Batch Operations JSON
Draft the new content using standard batch operations (`heading`, `append`, `insert-table`, `rich-text`, `horizontal-rule`).
Ensure paragraphs immediately following headings have `namedStyleType` set or reset to `NORMAL_TEXT`.

### Step 3: Ephemeral Validation (Optional for Complex Batches)
For updates with dense tables or 30+ operations, create an ephemeral scratch doc to validate syntax:
```bash
gdocs mutate create --title "Scratch Doc" --json
# Test batch insertion:
gdocs mutate batch SCRATCH_DOC_ID -f /tmp/batch_ops.json --index 1
# Cleanup:
gdocs mutate delete-doc SCRATCH_DOC_ID
```

### Step 4: Delete Target Range & Batch Insert
1. Delete the outdated range on the production document:
```bash
gdocs mutate delete DOC_ID START_INDEX END_INDEX --confirm
```
2. Insert the replacement content at the exact starting index:
```bash
gdocs mutate batch DOC_ID -f /tmp/batch_ops.json --index START_INDEX
```

### Step 5: Verify Integrity
Read structure or export to markdown to confirm that adjacent headings, trailing sections, and embedded images remain 100% intact:
```bash
gdocs readonly export DOC_ID --format md -o /tmp/verification.md
```
