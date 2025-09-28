# GView Analysis Engine - BehavioralPredicates

### Details

GView’s Analysis Engine: **catalog of user‑action predicates** and **suggestion rules** that guide the analyst.
For each predicate is included: **(what it means)** and **How to set** (what concrete UI/action flips it to `true`). Names follow your examples: `Opened(f)`, `ViewedMacros(f)`, `Suggest(ViewMacros(f))`, etc.

> **Conventions**
>
> * Facts are session-scoped unless you persist them: `SessionScoped(fact)`.
> * `ViewedX(f)` means “the analyst looked at X enough to mark it covered” (open the pane, scroll/expand the section, or hit a minimal dwell threshold).
> * `Suggest(Action(args))` is a fact you emit with a human-friendly explanation string, e.g., `Explain(Suggest(ViewMacros(f)), "This file contains obfuscated macros. Analyze them?")`.
> * Include **snooze/dismiss** facts so you don't nag: `Dismissed(Suggest(Action))`, `Snoozed(Suggest(Action), 15m)`.

---

### `BehavioralPredicates/`
- Contains **behavior-based facts** (e.g., how entities act, respond, or interact).
- `Predicates/` holds:
  - **YAML PredicateCards**: structured fact definitions.
  - **0.predicate_index.csv**: index for quick lookup.
- See the [Predicates list README](Predicates/README.md) for detailed notes.