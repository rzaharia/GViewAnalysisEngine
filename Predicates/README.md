# GView Analysis Engine - Predicates
## Components

### 1. `citations.yaml`
- Centralized record of all sources and references used in predicates and rules.
- Ensures traceability and attribution.

### 2. `FilePredicates/`
- Contains **file-based facts** (e.g., properties of files, metadata).
- `Predicates/` holds:
  - **YAML PredicateCards**: structured fact definitions.
  - **0.predicate_index.csv**: index for quick lookup.
- See the [FilePredicates README](FilePredicates/README.md) for detailed notes.

### 3. `BehavioralPredicates/`
- Contains **behavior-based facts** (e.g., how entities act, respond, or interact).
- Structured the same as `FilePredicates/`.
- See the [BehavioralPredicates README](BehavioralPredicates/README.md) for details.

### 4. `InferenceRules/`
- Encodes **inference logic** for reasoning using existing predicates and also to obtain new ones.
- Uses facts + citations to generate higher-level conclusions, explanations and options for the user.
- See the [InferenceRules README](InferenceRules/README.md) for detailed notes.
---

## Usage

1. Define new predicates in YAML under the relevant folder (`FilePredicates`, `BehavioralPredicates` or `InferenceRules`).
2. Update `0.predicate_index.csv` for indexing (available for the predicates).
3. Add or update inference rules under `InferenceRules/`.
4. Ensure sources are listed in `citations.yaml`.


## Loading & Performance

In the **initial implementation**, the engine **loaded each predicate/rule individually** by scanning folders. 
This caused noticeable overhead due to repeated file accesses. 

> To address this, we added build scripts that **compile all predicates and rules into a single compressed file**. 
> This reduces I/O costs and significantly improves **startup time**.

---

# Format explanation

## Predicate Schema: Field Explanations

Each predicate is stored as a YAML file (`PXXXX.Name.yaml` or `BXXXX.Name.yaml`) and follows a consistent schema. 

The following fields may appear in a predicate definition:

- **`id`**: Unique identifier. 
  - **PXXXX** for file predicates, **BXXXX** for behavioral predicates. 
  - Stable across versions to ensure reproducibility.

- **`name`**: Predicate name (CamelCase). Short, descriptive, and unique.

- **`signature`**: Formal signature showing the entity type and return value. 
  Example: `IsChm(f: File) -> Bool` means the predicate applies to a file and evaluates to a Boolean.

- **`category`**: Taxonomic grouping. Indicates where the predicate fits (e.g., `Static/TypeContainer`, `Behavior/SessionNavigation`).

- **`description`**: Single-line explanation of the predicate: what it detects, when it is set to `true`.

- **`scope`**: Object type and format. 
  - `object`: primary entity (`file`, `action`, `process`, etc.). 
  - `format`: expected file/container format (`CHM`, `OOXML`, `PE`, `generic`, etc.).

- **`mitre_attack`**: List of ATT&CK technique IDs relevant to this predicate (e.g., `T1221`, `T1055`). Empty if no direct mapping.

- **`trigger_logic`**: Conditions that activate the predicate. 
  - `positive`: indicators whose presence sets the fact to true (e.g., magic bytes, strings, headers). 
  - `negative`: indicators that exclude the fact.

- **`thresholds`**: Quantitative cutoffs for detection (e.g., entropy > 7.2, decompression ratio > 50). Empty `{}` if none.

- **`confidence_rules`**: Weighted evidence composition. Each rule describes a condition and its weight (sum normalizes to 1.0). Used for probabilistic confidence.

- **`evidence_binding`**: Pointers to where evidence is extracted. 
  - `captures`: byte ranges, file paths, telemetry logs.

- **`extraction`**: How evidence is obtained. 
  - `method`: e.g., `StaticParsing`, `DynamicMonitoring`, `Hybrid`. 
  - `failure_modes`: known parser weaknesses or caveats.

- **`false_positives`**: Known conditions that may incorrectly trigger the predicate.

- **`false_negatives`**: Known conditions that may miss true positives.

- **`provenance`**: Sources and authorship. 
  - `citations`: list of references (`ref: Cxxx`) with inline comments giving the title. 
  - `author`: attribution (e.g., `@gview-team`).

- **`implementation`**: Engineering state. 
  - `status`: `planned`, `implemented`, `supported`, or `deprecated`. 
  - `perf_cost`: heuristic runtime cost (`low`, `medium`, `high`).

- **`version`**: Schema/definition version number. Monotonic, increments when the definition changes.


### Example:
```yaml
id: P0005
name: IsChm
signature: 'IsChm(f: File) -> Bool'
category: Static/TypeContainer
description: Compiled HTML Help. **Set** if ITSF format (`ITSF` magic).
scope:
  object: file
  format: CHM
mitre_attack: []
trigger_logic:
  positive:
  - magic:
    - 49545346
  negative:
thresholds: {}
confidence_rules:
  - rule: primary_evidence
    weight: 1.0
evidence_binding:
  captures:
  - bytespan: O(0..512)
extraction:
  method: StaticParsing
  failure_modes: []
false_positives: []
false_negatives: []
provenance:
  citations:
  - ref: C001  # 'Invoice #31415 attached: Automated analysis of malicious Microsoft Office documents'
  - ref: C009  # 'Cheat Sheet for Analyzing Malicious Documents'
  author: '@gview-team'
implementation:
  status: planned
  perf_cost: low
version: 1
```