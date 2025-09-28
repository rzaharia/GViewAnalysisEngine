# GView Analysis Engine - FilePredicates

### Details

Each predicate contains a short description and what action is needed for it to be set to true.

### Conventions
> Names use `CamelCase` and assume the primary subject is a `File(f)` unless otherwise noted.
> * **Entities**: `File(f)`, `Process(p)`, `Conn(c)`, `User(u)`, `RegKey(k)`, `Service(s)`, `Task(t)`, `Volume(v)`.
> * **Source of truth**: prefix (optional) to remember where a fact came from, e.g., `Static:HasMacros(f)`, `Runtime:SpawnsPowerShell(p)`, `User:EnabledMacros(u,f)`.
> * **Aliases**: Define intentional hierarchies (e.g., `IsWord(f) → (IsDoc(f) ∨ IsDocx(f) ∨ IsDocm(f) ∨ IsRtf(f))`).

### Implementation Notes

* **Static extraction**

  * **File type**: magic bytes, MIME sniffing, container introspection (OLE/OOXML/ZIP/PDF).
  * **Office**: parse RELS, document XML, OLE streams; extract `vbaProject.bin` and walk the **VBA AST** to set macro predicates.
  * **PE/ELF/Mach-O**: imports/exports, section flags (e.g., `RWX`), overlay, signature, entropy per section.
  * **Content**: fast string scan, URL/IP regex, base64/hex blob detection, YARA rules for known artifacts.

* **Behavioral collection**
This could be collected from a Sandbox environment

  * **File system**: monitor create/write/rename/delete; attribute changes (hidden/ADS); track **write→execute** chains.
  * **Process**: parent/child trees; command-lines; sensitive API calls (CreateRemoteThread, WriteProcessMemory…); module loads.
  * **Network**: flow capture (destinations, timing), protocol classification (HTTP(S), DNS, SMB), certificate observation; beaconing analytics.
  * **Registry/Services/Tasks**: observe creation/modification; collect diffs for persistence keys.
  * **User actions**: hook UI/Office telemetry where feasible; correlate browser/email provenance (MOTW, referrers).

---

### `FilePredicates/`
- Contains **file-based facts** (e.g., properties of files, metadata).
- `Predicates/` holds:
  - **YAML PredicateCards**: structured fact definitions.
  - **0.predicate_index.csv**: index for quick lookup.
- See the actual [Predicates list README](Predicates/README.md) for detailed notes.
