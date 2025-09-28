# GView Analysis Engine

GView Analysis Engine is a fact-driven reasoning framework designed to help analysts interpret and triage complex forensic data.
It provides a **catalog of predicates** (file-based and behavioral) and a library of **inference rules** that derive higher-level facts from raw observations.

---

## Overview

- **File-based predicates**: **283** static/dynamic facts derived from files (formats, macros, packers, network indicators, etc.).
- **Behavioral predicates**: **102** user-action and analyst-interaction facts (e.g., `ViewedMacros(f)`, `Opened(f)`, `AddedToCase(f,caseId)`).
- **Inference rules**: 
  * **156 rules** that lead to additional flags. 
  * **198 rules** for use recommandations. 

> All predicates carry **citations**. They are **inspired by peer-reviewed papers, incident reports, or industry write-ups** of real attacks. 
> This ensures **traceable provenance** and **academic rigor**.

## Repository Structure

- **LICENSE** 
- **.gitignore**
- **README.md** - This file
- **Predicates/**
  - **citations.yaml** - All reference sources for predicates and rules
  - **FilePredicates/** 
    - **Predicates/** - YAML PredicateCards + `0.predicate_index.csv` 
    - **README.md** - Notes on file-based facts 
  - **BehavioralPredicates/**
    - **Predicates/** - YAML PredicateCards + `0.predicate_index.csv` 
    - **README.md** - Notes on behavioral facts 
  - **InferenceRules/** 
    - **Rules/** - Inferece rules that produce flag results
    - **Suggestions/** - Inferece rules that offer suggestions to the user
  - **README.md** - Notes of Predicates

## Documentation inside each folder

- [`Predicates/README.md`](Predicates/README.md) 
  Has an introduction for the **predicates**.

---

## Next Steps

- Explore the **FilePredicates**, **BehavioralPredicates** and **InferenceRules** folders for detailed conventions. 
- See the **Rules** folder for inference logic that combines low-level facts into higher-level flags (`IsSuspicious`, `IsMalicious`, `Suggest(...)`).
- Use the `citations.yaml` file to trace every predicate/rule back to its source.

## License
See [LICENSE](LICENSE) for details.