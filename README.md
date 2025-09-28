# GView Analysis Engine

GView Analysis Engine is a fact-driven reasoning framework designed to help analysts interpret and triage complex forensic data.  
It provides a **catalog of predicates** (file-based and behavioral) and a library of **inference rules** that derive higher-level facts from raw observations.

---

## Overview

- **File-based predicates**: **283** static/dynamic facts derived from files (formats, macros, packers, network indicators, etc.).
- **Behavioral predicates**: **102** user-action and analyst-interaction facts (e.g., `ViewedMacros(f)`, `Opened(f)`, `AddedToCase(f,caseId)`).
- **Inference rules**:  
  * **X rules** for files.  
  * **Y rules** for behaviors.  

> All predicates carry **citations**. They are **inspired by peer-reviewed papers, incident reports, or industry write-ups** of real attacks.  
> This ensures **traceable provenance** and **academic rigor**.

## Repository Structure

- **LICENSE**  
- **.gitignore**  
- **README.md** ← This file  
- **Predicates/**  
  - **citations.yaml** - All reference sources for predicates and rules  
  - **FilePredicates/**  
    - **Predicates/** - YAML PredicateCards + `0.predicate_index.csv`  
    - **README.md** - Notes on file-based facts  
  - **BehavioralPredicates/**  
    - **Predicates/** - YAML PredicateCards + `0.predicate_index.csv`  
    - **README.md** - Notes on behavioral facts  
  - **Rules/**  
    - `...` ← Inference rules (file + behavioral)  
  - **README.md** - Notes of Predicates

## Documentation inside each folder

- [`Predicates/README.md`](Predicates/README.md)  
  Has an introduction for the **predicates**.

- [`Predicates/FilePredicates/README.md`](Predicates/FilePredicates/README.md)  
  Explains conventions for **file facts**, entity naming, and static/behavioral collection methods.

- [`Predicates/BehavioralPredicates/README.md`](Predicates/BehavioralPredicates/README.md)  
  Explains conventions for **behavioral facts**, user-action predicates, and suggestion rules.

- `Predicates/citations.yaml`  
  Full list of all papers, ATT&CK techniques, advisories, and blogs cited.

---

## Next Steps

- Explore the **FilePredicates** and **BehavioralPredicates** folders for detailed conventions.  
- See the **Rules** folder for inference logic that combines low-level facts into higher-level flags (`IsSuspicious`, `IsMalicious`, `Suggest(...)`).
- Use the `citations.yaml` file to trace every predicate/rule back to its source.

## License
See [LICENSE](LICENSE) for details.