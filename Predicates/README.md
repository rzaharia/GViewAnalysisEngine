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

### 4. `Rules/`
- Encodes **inference logic** for reasoning over both file and behavioral predicates.
- Uses facts + citations to generate higher-level conclusions.

---

## Usage

1. Define new predicates in YAML under the relevant folder (`FilePredicates` or `BehavioralPredicates`).
2. Update `0.predicate_index.csv` for indexing.
3. Add or update inference rules under `Rules/`.
4. Ensure sources are listed in `citations.yaml`.


## Loading & Performance

In the **initial implementation**, the engine **loaded each predicate/rule individually** by scanning folders.  
This caused noticeable overhead due to repeated file accesses.  

> To address this, we added build scripts that **compile all predicates and rules into a single compressed file**.  
> This reduces I/O costs and significantly improves **startup time**.

---