# GView Analysis engine
## Inference rules

Our rules are split into two categories:
1. Rules that lead to **additional flags**.
2. Rules that **offer suggestions** to the user.

Below is a **large rulebook of inference rules** that produce **actionable suggestions** for the analyst.
Rules use **file predicates** (static/dynamic characteristics) and **user‑action predicates** (what the analyst has/hasn’t viewed or done). I include **file‑only**, **user‑only**, and **mixed** rules. Each rule is written as:

```
[ID]  Condition(s)  →  Suggest(Action(args))
      {severity: info|warn|high|critical, message: "...", cooldown: 5m|30m|… , window: e.g., 10m, tags:[...]}
```

> **Conventions**
>
> * `Within(T)` applies a temporal window to *all* listed events unless otherwise stated.
> * Use `Dismissed(Suggest(X))` / `Snoozed(Suggest(X), Δt)` to mute repeats; engine should respect `cooldown`.
> * Action names are the buttons you show in UI (e.g., `ViewMacros(f)`, `DecodeBase64(f)`, `LaunchSandbox(f)`).
> * This rulebook assumes the predicate sets proposed in earlier responses (e.g., `IsWord`, `HasMacros`, `ViewedMacros`, `TriesToAccessTheInternet`, etc.).

---


## Rule & Suggestion YAML Format

## 1) Inference Rules (`IXXXX`)

### 1.1 Overview
- **Purpose:** encode machine‑derivable conclusions (postconditions) from matched predicates and/or telemetry observations.
- **File name:** `I####.<CamelCaseName>.yaml` (e.g., `I3107.MacroNetAccessIsMalicious.yaml`).
- **ID:** `^I\d{4}$` (zero‑padded to 4 digits; start at `I0001`).
- **`description`:** single line; concise and declarative.

### 1.2 Field Specification
| Field | Type / Allowed Values | Required | Notes |
|---|---|---:|---|
| `id` | `I####` | ✅ | Zero‑padded 4 digits. Unique in corpus. |
| `name` | PascalCase string | ✅ | Short and descriptive; ≤80 chars. |
| `signature` | `LHS → RHS` | ✅ | Use `∧` for AND; **no OR** (split into multiple rules). `LHS/RHS` are predicate forms like `Predicate(f)`; no side effects. |
| `category` | `Behavioral/<Domain>` | ✅ | Examples: `Behavioral/Network`, `Behavioral/Persistence`, `Behavioral/Privilege`, `Behavioral/Ransomware`, `Behavioral/Exfiltration`, etc. Keep a stable taxonomy. |
| `scope.object` | `file` \| `process` \| `action` \| `network_flow` | ✅ | Choose the primary entity the rule asserts about. |
| `scope.postconditions` | List of one of:<br>• `- Flag: <BooleanPredicate(args)>`<br>• `- Derive: <AuxPredicate(args)>` | ✅ | Use `Flag:` for terminal labels (`IsMalicious`, `IsSuspicious`, `LikelyBenign`). Use `Derive:` for intermediate facts. |
| `description` | Single line string | ✅ | No linebreaks; ≤200 chars. |
| `trigger_logic.antecedent` | List of `Predicate(args)=true` | ✅ | Each antecedent is explicit equality to `true`. Prefer dedicated negative predicates over negation symbols. |
| `trigger_logic.consequent` | List of `Predicate(args)=true` | ✅ | Usually 1 item; mirrors `scope.postconditions`. |
| `evidence_binding.requires` | List of `{artifact, fields[]}` | ✅ | Declare **minimum** telemetry required to evaluate and explain decisions. |
| `evidence_binding.retention_hint` | String | – | Human‑readable retention window (e.g., "Store ±120s around key events"). |
| `confidence.base` | Float `[0..1]` | ✅ | Base (prior) confidence for the rule firing in your environment. |
| `confidence.modifiers` | List of strings `if <condition>: +/-X.XX` | – | Grammar: `if <telemetry/predicate condition>: +0.05`. Engine clamps final score to `[0..1]`. |
| `confidence.calibration` | String | – | Reference to calibration profile (`isotonic_YYYY_MM`, `platt_YYYY_MM`). |
| `severity.level` | `info` \| `low` \| `medium` \| `high` \| `critical` | ✅ | Rule impact, not confidence. |
| `severity.rationale` | String | – | Why this rule is impactful (operator‑focused). |
| `conflict_handling.contradicts` | List of references | – | Names or IDs of rules that may disagree (e.g., benign auto‑update heuristics). |
| `conflict_handling.resolution` | String | – | Deterministic tie‑breaker (e.g., prefer higher confidence unless allowlisted). |
| `adversary_evasion.known_bypasses` | String[] | – | How actors bypass this detection. |
| `adversary_evasion.mitigations` | String[] | – | What to instrument/monitor to close gaps. |
| `provenance.citations` | List of `{id: C###}` | ✅ | Use canonical `citations.yaml`; add the paper/report title as an inline YAML comment. |
| `provenance.author` | String | ✅ | Who authored/owns the rule. |
| `implementation.status` | `planned` \| `supported` \| `implemented` \| `deprecated` | ✅ | Paper submissions usually use `planned` or `supported`. |
| `implementation.perf_cost` | `low` \| `medium` \| `high` | ✅ | Relative runtime/telemetry cost. |
| `version` | Integer | ✅ | Start at `1`; bump on breaking changes. |

### Example 
```yaml
id: I3107
name: MacroNetAccessIsMalicious
signature: IsSuspicious(f) ∧ DownloadsFileFromInternet(f) → IsMalicious(f)
category: Behavioral/Network
scope:
  object: file
  postconditions:
    - Flag: IsMalicious(f)
description: If a file previously classified as suspicious initiates network activity that downloads an executable or script payload, elevate to malicious.
trigger_logic:
  antecedent:
    - IsSuspicious(f)=true
    - DownloadsFileFromInternet(f)=true
  consequent:
    - IsMalicious(f)=true
evidence_binding:
  requires:
    - artifact: netflow
      fields: [dst_ip, dst_domain, url, http_method, bytes_in, sha256_downloaded]
    - artifact: process_tree
      fields: [parent_pid, cmdline, signer_status]
  retention_hint: "Store 60s before and after the HTTP 200 event."
confidence:
  base: 0.85
  modifiers:
    - if sha256_downloaded is PE and Unsigned(sha256_downloaded): +0.10
    - if ParentProcess is Office and HasMacros(f): +0.05
  calibration: isotonic_2025_09
severity:
  level: high
  rationale: "Observed delivery of new on-disk payload from untrusted origin."
conflict_handling:
  contradicts: [Rule: R-1980 'BenignAutoUpdate']  # see Section 5
  resolution: "Prefer higher confidence unless allowlist(domain) applies."
adversary_evasion:
  known_bypasses: ["Chunked download over WMI", "BITS jobs via LOLBins"]
  mitigations: ["Monitor BITS events", "Reassemble TLS SNI + JA3 signals"]
provenance:
  citations:
    - id: C021  # 'A PE header-based method for malware detection using clustering and deep embedding techniques'
    - id: C025  # 'BITS Jobs (T1197)'
  author: "@gview-team"
implementation:
  status: planned
  perf_cost: medium
version: 1
```

### 1.3 Common Artifacts (`evidence_binding.requires.artifact`)
- `netflow` (`dst_ip`, `dst_domain`, `url`, `proto`, `http_method`, `bytes_in/out`, `ja3`, `sni`)
- `process_tree` (`parent_pid`, `pid`, `cmdline`, `signer_status`, `child_processes`)
- `registry_events` (`path`, `value`, `op`)
- `services` (`name`, `image_path`, `start_type`)
- `scheduled_tasks` (`name`, `command`)
- `dns_logs` (`qname`, `rcode`, `dga_score`)
- `tls` (`issuer`, `subject`, `self_signed`, `valid_from/to`)
- `pe_static`, `pdf_objects`, `archive_manifest`, `wmi_events`, `cloud_api`, `timeline`, etc.

---

## 2) Suggestion Rules (`FXXXX`)

### 2.1 Overview
- **Purpose:** encode **operator assistance** (UI suggestions) triggered by matched predicates. They **do not** assert maliciousness; they **guide** the analyst.
- **File name:** `F####.<CamelCaseName>.yaml` (e.g., `F0001.ViewMacrosIfIsWordAndHasMacros.yaml`).
- **ID:** `^F\d{4}$`. Preserve any **source code** (e.g., `code: F-0001`) from the original list.
- **`description`:** single line, actionable.

### 2.2 Field Specification
| Field | Type / Allowed Values | Required | Notes |
|---|---|---:|---|
| `id` | `F####` | ✅ | Zero‑padded; unique in suggestion corpus. |
| `code` | String (source label) | – | Preserve original bracketed identifier (e.g., `F-0001`) for traceability. |
| `name` | PascalCase string | ✅ | Prefer Action+Condition style (e.g., `ViewPdfJsIfIsPdfAndPdfHasJavaScript`). |
| `signature` | `LHS → Suggest(Action(args))` | ✅ | Same `∧` semantics as inference rules; **only** `Suggest(...)` on RHS. |
| `category` | `Suggestion/<Domain>` | ✅ | E.g., `Suggestion/Office`, `Suggestion/PdfRtfOle`, `Suggestion/Scripts`, `Suggestion/Archive`, `Suggestion/PE`, `Suggestion/Lnk`, `Suggestion/General`. |
| `scope.object` | Usually `file` | ✅ | Entity the suggestion targets. |
| `scope.format` | String | – | Optional hint (`OOXML/OLE`, `PDF/RTF/OLE`, `Script`, `ZIP/RAR/7z`, `LNK`, …). |
| `description` | Single line string | ✅ | Clear operator intent. |
| `trigger_logic.antecedent` | List of `Predicate(args)=true` | ✅ | Conditions for showing the suggestion. |
| `trigger_logic.consequent` | `Suggest(Action(args))` | ✅ | Always a single line. |
| `action.suggest` | Action token | ✅ | Routed by UI/engine (e.g., `ViewMacros(f)`, `ViewPdfObjects(f)`, `RunDeobfuscation(f)`). |
| `message` | Short string | ✅ | The user‑facing prompt. ≤120 chars. |
| `explanation` | Short paragraph | ✅ | Why this suggestion matters; concise and jargon‑light. |
| `cooldown` | Duration (`Xs`, `Xm`, `Xh`) | ✅ | Throttles re‑prompting per `(id, action, object)` key. Examples: `30m`, `2h`. |
| `tags` | Lowercase strings[] | – | For UI grouping (e.g., `office`, `macro`, `pdf`, `lnk`). |
| `severity.level` | `info` \| `low` \| `medium` \| `high` | ✅ | **Operator urgency**, not maliciousness. |
| `provenance.citations` | `{id: C###}` list | – | Cite technique/whitepaper that motivates the suggestion. |
| `provenance.author` | String | ✅ | Author/owner. |
| `implementation.status` | `planned` \| `supported` \| `implemented` | ✅ | Roadmap state. |
| `implementation.perf_cost` | `low` \| `medium` | ✅ | Suggestion evaluation cost. |
| `version` | Integer | ✅ | Start at `1`. |

### Example 
```yaml
id: F0001
code: F-0001
name: ViewMacrosIfIsWordAndHasMacros
signature: 'IsWord(f) ∧ HasMacros(f) → Suggest(ViewMacros(f))'
category: Suggestion/Office
scope:
  object: file
  format: OOXML/OLE
description: Recommend opening the Macro Viewer when a Word document with macros is detected.
trigger_logic:
  antecedent:
    - IsWord(f)=true
    - HasMacros(f)=true
  consequent:
    - Suggest(ViewMacros(f))
action:
  suggest: ViewMacros(f)
message: 'Macros present. Open the Macro Viewer?'
explanation: 'Office macros are a common initial execution vector; reviewing macro content improves triage and reveals downloader or persistence code.'
cooldown: '30m'
tags:
  - office
  - macro
severity:
  level: high
provenance:
  citations:
    - id: C001  # 'Invoice #31415 attached: Automated analysis of malicious Microsoft Office documents'
    - id: C009  # 'Cheat Sheet for Analyzing Malicious Documents'
    - id: C045  # 'User Execution: Malicious File (T1204.002)'
  author: '@gview-team'
implementation:
  status: planned
  perf_cost: low
version: 1
```

---

# Future work 

* **Where to fire**: evaluate rules on (a) file load, (b) predicate change (new telemetry), (c) panel open/close, and (d) timed intervals for `Within(T)` windows.
* **How to display**: couple `Suggest(Action)` with `Explain(…, message)` and a button. Add `severity` as color/priority.
* **Noise control**: group similar suggestions; respect `Dismissed` and `Snoozed`; never re‑suggest within `cooldown`.
* **Safety checks**: automatically prepend guards (e.g., only propose `LaunchSandbox` if sandbox exists; only propose `SafeExtract` if a safe path is configured).

## 1) Inference Rules (`IXXXX`)
Extend GView to process and optmise the entire process based on all the possible present fields.

### 1.3 Common Artifacts (`evidence_binding.requires.artifact`)
- `netflow` (`dst_ip`, `dst_domain`, `url`, `proto`, `http_method`, `bytes_in/out`, `ja3`, `sni`)
- `process_tree` (`parent_pid`, `pid`, `cmdline`, `signer_status`, `child_processes`)
- `registry_events` (`path`, `value`, `op`)
- `services` (`name`, `image_path`, `start_type`)
- `scheduled_tasks` (`name`, `command`)
- `dns_logs` (`qname`, `rcode`, `dga_score`)
- `tls` (`issuer`, `subject`, `self_signed`, `valid_from/to`)
- `pe_static`, `pdf_objects`, `archive_manifest`, `wmi_events`, `cloud_api`, `timeline`, etc.

### 1.4 Validation/Linting (Inference Rules)
- `description` is **single line**.
- At least **one** `antecedent` and **one** `consequent`.
- `scope.postconditions` must correspond to the `consequent`.
- No unknown `artifact` names; prefer the controlled vocabulary above.
- Confidence is clamped to `[0,1]` after modifiers.
- All `citations.id` resolve against `citations.yaml`; avoid duplicates.

## 2) Suggestion Rules (`FXXXX`)
To fully use these proposed features, the UI component in GView might need an overhaul. The rust variant [AppCUI-rs](https://github.com/gdt050579/AppCUI-rs) offers what we might need but it will need integration with C++.

### 2.3 UX/Engine Behavior for `cooldown`
- **Scope key:** `(id, action.suggest, scope.object, object_identifier)`; default per‑file suppression.
- **Reset conditions:** new evidence, analyst explicitly triggers the action, or case context changes.

### 2.4 Authoring Guidance (Suggestions)
- Make `message` **actionable** (e.g., “Open Macro Viewer?”) and `explanation` **educational** (“why this matters”).
- Tag consistently for navigation and analytics dashboards.
- Suggestions must be **non‑binding** and **never** change classification flags.

---

## 3) Validation Checklist (CI)
- IDs and filenames match (e.g., `I####`/`F####` ↔ file prefix).
- `description` is single‑line; no trailing spaces.
- `trigger_logic.antecedent` and `consequent` are non‑empty and well‑formed.
- `scope.postconditions` ↔ `consequent` (for inference rules).
- All `artifact` names are from the controlled list; all `provenance.citations.id` exist in `citations.yaml`.
- `severity.level` in the allowed set; `confidence.base ∈ [0,1]`.
- **Suggestion rules:** `action.suggest` present, `cooldown` parses, `message` ≤120 chars.

---

## 4) Authoring Tips
- Prefer **observable** conditions in `antecedent` (deterministic, parseable).
- Put **reasoning** into `explanation`/`rationale` instead of bloating `description`.
- Use `adversary_evasion` to acknowledge blind spots and list practical mitigations (good for peer‑review).
- Keep `perf_cost` honest—reviewers value transparency on deployability.

---

### See the [rules detailed list](Rules/README.md) for detailed notes on intermediary rules
### See the [suggestions detailed list](Suggestions/README.md) for detailed notes on suggestions