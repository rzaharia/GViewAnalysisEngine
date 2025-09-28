# GView Analysis engine
## Behaviroral Facts

GView’s Analysis Engine: **catalog of user‑action predicates** and **suggestion rules** that guide the analyst.
For each predicate is included: **(what it means)** and **How to set** (what concrete UI/action flips it to `true`). Names follow your examples: `Opened(f)`, `ViewedMacros(f)`, `Suggest(ViewMacros(f))`, etc.

> **Conventions**
>
> * Facts are session-scoped unless you persist them: `SessionScoped(fact)`.
> * `ViewedX(f)` means “the analyst looked at X enough to mark it covered” (open the pane, scroll/expand the section, or hit a minimal dwell threshold).
> * `Suggest(Action(args))` is a fact you emit with a human-friendly explanation string, e.g., `Explain(Suggest(ViewMacros(f)), "This file contains obfuscated macros. Analyze them?")`.
> * Include **snooze/dismiss** facts so you don’t nag: `Dismissed(Suggest(Action))`, `Snoozed(Suggest(Action), 15m)`.

---

## 1) Session & Navigation

* **Opened(f)** — File was opened in GView.
  *How to set:* when the file tab loads or becomes active.
* **Closed(f)** — File tab closed.
  *How to set:* on tab close.
* **SwitchedFocus(pane)** — User switched to a given pane (Hex, Strings, PE, Macros…).
  *How to set:* pane/tab change event.
* **Pinned(f)** — Pinned for quick access.
  *How to set:* on pin toggle.
* **AddedToCase(f, caseId)** — Added to current case/session.
  *How to set:* on “Add to case”.
* **MarkedPriority(f, level)** — Analyst priority tag (low/med/high).
  *How to set:* on priority menu.
* **OpenedSafely(f)** — Opened with non-executing safe viewer (no active scripts/macros).
  *How to set:* when safe-view mode chosen.
* **SwitchedWorkspace(name)** — Analyst switched work context.
  *How to set:* workspace change.

**Suggestions (examples)**

* `Opened(f) ∧ ¬Pinned(f) ∧ IsHighRiskType(f) → Suggest(Pin(f))` — *“Pin this high‑risk file to stay on top of it?”*
* `Opened(f) ∧ ¬OpenedSafely(f) ∧ IsActiveContentCapable(f) → Suggest(OpenInSafeView(f))` — *“Open in protected/safe view to avoid executing active content?”*

---

## 2) Hashing, Reputation & Provenance

* **ComputedHashes(f)** — SHA‑256/MD5 calculated.
  *How to set:* on “Compute hashes”.
* **ViewedHashes(f)** — Hashes displayed/acknowledged.
  *How to set:* open Hashes panel or copy a hash.
* **QueriedThreatIntel(f, source)** — Searched hash/IOC in a TI source (local/remote).
  *How to set:* TI lookup API call returns.
* **ViewedMOTW(f)** — Mark-of-the-Web inspected.
  *How to set:* open Provenance panel or MOTW tooltip.
* **ViewedOrigin(f)** — Source path/referrer reviewed (email, URL, disk image).
  *How to set:* open Origin panel.
* **ViewedSignature(f)** — Digital signature pane opened.
  *How to set:* open Signatures tab.
* **VerifiedSignature(f)** — Chain/timestamp verified.
  *How to set:* run verify routine.

**Suggestions**

* `Opened(f) ∧ ¬ComputedHashes(f) → Suggest(ComputeHashes(f))` — *“Compute hashes to enable correlation and intel lookups?”*
* `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any) → Suggest(QueryThreatIntel(f))` — *“Check reputation and prior sightings?”*
* `IsSigned(f) ∧ ¬ViewedSignature(f) → Suggest(ViewSignature(f))` — *“Inspect signer and timestamp?”*
* `MarkOfTheWeb(f) ∧ ¬ViewedMOTW(f) → Suggest(ViewMOTW(f))` — *“This came from the Internet. Review MOTW details?”*

---

## 3) Strings, Blobs & Carving

* **ViewedStrings(f)** — Strings pane opened.
  *How to set:* open Strings tab; dwell > N seconds.
* **ExtractedStrings(f)** — Strings export action performed.
  *How to set:* on export or copy-all.
* **NormalizedStrings(f)** — Case/Unicode/encoding normalization applied.
  *How to set:* use normalization controls.
* **ExtractedUrls(f)** — URL extraction run.
  *How to set:* “Extract URLs” command completes.
* **DecodedBase64Blobs(f)** / **DecodedHexBlobs(f)** — Decoders run.
  *How to set:* decode tool used.
* **CarvedEmbeddedFiles(f)** — Embedded archives/PEs carved.
  *How to set:* “Carve embedded” command.
* **ViewedDecodedResults(f)** — Decoded outputs opened.
  *How to set:* open decoder results pane.

**Suggestions**

* `ContainsBase64Blobs(f) ∧ ¬DecodedBase64Blobs(f) → Suggest(DecodeBase64(f))` — *“Base64 blobs detected. Decode them?”*
* `ContainsUrl(f) ∧ ¬ExtractedUrls(f) → Suggest(ExtractUrls(f))` — *“Extract URLs for pivoting?”*
* `ContainsEmbeddedArchive(f) ∧ ¬CarvedEmbeddedFiles(f) → Suggest(CarveEmbedded(f))` — *“Carve embedded payloads?”*
* `ExtractedUrls(f) ∧ ¬ViewedDecodedResults(f) → Suggest(ViewDecoded(f))` — *“Review decoded artifacts now?”*

---

## 4) Office / Word Macros (static)

* **ViewedMacros(f)** — VBA project opened.
  *How to set:* open Macro viewer or `vbaProject.bin`.
* **DecompiledVBA(f)** — Decompiled to readable source.
  *How to set:* decompiler run.
* **DeobfuscatedVBA(f)** — Obfuscation passes applied.
  *How to set:* deobfuscator finish.
* **ViewedAutoExecs(f)** — AutoOpen/Document\_Open etc. inspected.
  *How to set:* click “AutoExecs”.
* **ViewedSuspiciousCalls(f)** — Shell/URLDownloadToFile/etc. list opened.
  *How to set:* click suspicious-calls filter.
* **ViewedExternalTemplateRels(f)** — `rels` pointing remote reviewed.
  *How to set:* open External Templates panel.
* **ExportedMacros(f)** — Exported VBA modules.
  *How to set:* on export.

**Suggestions**

* `IsWord(f) ∧ HasMacros(f) ∧ ¬ViewedMacros(f) → Suggest(ViewMacros(f))` — *“Macros present. Analyze them?”*
* `HasMacroObfuscation(f) ∧ ¬DeobfuscatedVBA(f) → Suggest(DeobfuscateVBA(f))` — *“Obfuscation detected. Run deobfuscation?”*
* `ContainsExternalTemplateRef(f) ∧ ¬ViewedExternalTemplateRels(f) → Suggest(ViewExternalTemplates(f))` — *“Document loads external template. Inspect references?”*
* `HasSuspiciousMacroFunctionCalls(f) ∧ ¬ViewedSuspiciousCalls(f) → Suggest(ViewSuspiciousCalls(f))` — *“Suspicious macro calls found. Review the list?”*

---

## 5) Excel / XLM, PowerPoint

* **ViewedXlmSheets(f)** — Excel 4.0 macro sheet viewer opened.
  *How to set:* open XLM pane.
* **ViewedHiddenSheets(f)** — VeryHidden/Hidden inspected.
  *How to set:* click hidden sheet list.
* **ViewedPptActions(f)** — PPT action buttons/macros inspected.
  *How to set:* open Actions pane.

**Suggestions**

* `IsExcel(f) ∧ HasXlm4Macro(f) ∧ ¬ViewedXlmSheets(f) → Suggest(ViewXlmSheets(f))`
* `IsExcel(f) ∧ HasHiddenSheets(f) ∧ ¬ViewedHiddenSheets(f) → Suggest(ViewHiddenSheets(f))`

---

## 6) PDFs & OLE/RTF

* **ViewedPdfObjects(f)** — Object tree opened.
  *How to set:* open PDF object viewer.
* **ViewedPdfJs(f))** — JavaScript streams opened.
  *How to set:* open JS subpane.
* **ViewedRtfControls(f)** — RTF control words list opened.
  *How to set:* open RTF parser pane.

**Suggestions**

* `IsPdf(f) ∧ PdfHasJavaScript(f) ∧ ¬ViewedPdfJs(f) → Suggest(ViewPdfJavaScript(f))`
* `IsRtf(f) ∧ ContainsKnownExploitArtifacts(f) ∧ ¬ViewedRtfControls(f) → Suggest(ViewRtfControls(f))`

---

## 7) PE/ELF/Mach‑O Static

* **ViewedHeaders(f)** — Main binary headers opened (PE/ELF/Mach‑O).
  *How to set:* open header pane.
* **ViewedSections(f)** — Section table inspected.
  *How to set:* open sections pane.
* **ViewedImports(f)** / **ViewedExports(f)** — Import/export tables viewed.
  *How to set:* open Imports/Exports.
* **ViewedResources(f)** — Resources tree opened.
  *How to set:* open resources.
* **ViewedOverlay(f)** — Overlay/extra data pane opened.
  *How to set:* open overlay pane.
* **ViewedEntropy(f)** — Entropy chart opened.
  *How to set:* open entropy view.
* **RanPackerId(f)** — Packer ID tool run.
  *How to set:* execute packer-id cmd.
* **DecompiledNative(f)** — Ran decompiler.
  *How to set:* decompiler completes.
* **ViewedSignatureProblems(f)** — Invalid/revoked signature panel opened.
  *How to set:* click “Signature issues”.

**Suggestions**

* `IsPe(f) ∧ ¬ViewedImports(f) → Suggest(ViewImports(f))` — *“Review imported APIs for intent?”*
* `HasHighEntropy(f) ∧ ¬RanPackerId(f) → Suggest(IdentifyPacker(f))` — *“High entropy suggests packing. Identify packer?”*
* `IsPe(f) ∧ ¬ViewedResources(f) ∧ ContainsEmbeddedExecutable(f) → Suggest(ViewResources(f))`

---

## 8) Scripts & HTA/JS/VBS/PS1

* **ViewedScriptSource(f)** — Script source shown (beautified if applicable).
  *How to set:* open script viewer.
* **BeautifiedScript(f)** — Minified source reformatted.
  *How to set:* run beautifier.
* **ViewedEvalChains(f)** — `eval`/`ExecuteGlobal`/`AddType` chains listed.
  *How to set:* open dynamic-eval pane.
* **DecodedScriptPayloads(f)** — Decoded payloads side-pane opened.
  *How to set:* decoder success.

**Suggestions**

* `IsScript(f) ∧ HasObfuscatedStrings(f) ∧ ¬BeautifiedScript(f) → Suggest(BeautifyScript(f))`
* `ContainsDownloaderCode(f) ∧ ¬ViewedEvalChains(f) → Suggest(ViewDynamicEval(f))`

---

## 9) Archives / Installers

* **ViewedArchiveManifest(f)** — Member list opened.
  *How to set:* open archive pane.
* **ExtractedArchiveSafely(f)** — Extracted to sandbox/readonly path.
  *How to set:* safe-extract command.
* **ViewedDoubleExtensions(f)** — “.pdf.exe” list opened.
  *How to set:* open heuristic subpane.
* **ViewedMsiCustomActions(f)** — MSI CustomAction table opened.
  *How to set:* open MSI pane.

**Suggestions**

* `IsArchive(f) ∧ ArchiveIsPasswordProtected(f) ∧ ¬ExtractedArchiveSafely(f) → Suggest(SafeExtract(f))`
* `IsInstaller(f) ∧ MsiRunsCustomAction(f) ∧ ¬ViewedMsiCustomActions(f) → Suggest(ViewMsiCustomActions(f))`

---

## 10) Dynamic / Sandbox

* **LaunchedInSandbox(f)** — Dynamic run initiated.
  *How to set:* sandbox start event.
* **ViewedProcessTree(f)** — Process graph opened.
  *How to set:* open process tree pane.
* **ViewedNetworkBehavior(f)** — Dynamic network activity viewed.
  *How to set:* open Net view or PCAP.
* **ViewedFileSystemActivity(f)** — FS timeline opened.
  *How to set:* open FS pane.
* **ViewedRegistryActivity(f)** — Registry timeline opened.
  *How to set:* open Registry pane.
* **CapturedPcap(f)** — PCAP capture saved.
  *How to set:* capture/export.
* **AppliedApiMonitors(f)** — API hooking/tracing enabled.
  *How to set:* start API monitor.
* **PausedExecution(f)** / **HaltedExecution(f)** — Sandbox paused/stopped.
  *How to set:* pause/stop pressed.

**Suggestions**

* `TriesToAccessTheInternet(f) ∧ ¬ViewedNetworkBehavior(f) → Suggest(ViewNetwork(f))` — *“You haven’t checked network activity yet.”*
* `WritesToTempExecutable(f) ∧ ¬ViewedFileSystemActivity(f) → Suggest(ViewFileWrites(f))`
* `CreatesRunKey(f) ∧ ¬ViewedRegistryActivity(f) → Suggest(ViewRegistryChanges(f))`
* `DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f) → Suggest(ViewProcessTree(f))`

---

## 11) Persistence & Privilege

* **ViewedRunKeys(f)** — Startup Run/RunOnce inspected.
  *How to set:* open RunKeys pane.
* **ViewedScheduledTasks(f)** — New tasks inspected.
  *How to set:* open Tasks pane.
* **ViewedServices(f)** — Service creation/modification inspected.
  *How to set:* open Services pane.
* **ViewedWmiSubscriptions(f)** — WMI event consumers opened.
  *How to set:* open WMI pane.
* **ViewedUacEvents(f)** — Elevation/UAC activity inspected.
  *How to set:* open UAC pane.
* **ViewedTokenPrivileges(f)** — Token privilege changes inspected.
  *How to set:* open Token pane.

**Suggestions**

* `PersistenceIndicatorsPresent(f) ∧ ¬(ViewedRunKeys(f) ∨ ViewedScheduledTasks(f) ∨ ViewedServices(f)) → Suggest(ViewPersistence(f))`
* `RequestsUacElevation(f) ∧ ¬ViewedUacEvents(f) → Suggest(ViewUac(f))`

---

## 12) Network Intel & Certificates

* **ResolvedDomains(f)** — DNS resolution list viewed.
  *How to set:* open DNS subpane.
* **ViewedTlsCertificates(f)** — Certificates from sessions inspected.
  *How to set:* open TLS certs.
* **GeoMappedConnections(f)** — Destinations mapped.
  *How to set:* open Geo map.
* **TaggedC2Endpoints(f)** — Analyst labeled endpoints as C2/suspicious.
  *How to set:* tag action.

**Suggestions**

* `UsesHTTPSRequests(f) ∧ ¬ViewedTlsCertificates(f) → Suggest(ViewTlsCertificates(f))`
* `BeaconingPattern(f) ∧ ¬ResolvedDomains(f) → Suggest(ViewDnsQueries(f))`

---

## 13) Ransomware / Exfil Focus

* **ViewedEncryptionMonitor(f)** — Monitored encryption rate.
  *How to set:* open Encryption Monitor.
* **ViewedShadowCopyEvents(f)** — VSS deletions inspected.
  *How to set:* open VSS pane.
* **ViewedExfilTimeline(f)** — Upload volume/time viewed.
  *How to set:* open Exfil panel.
* **ViewedRansomNotes(f)** — Note artifacts reviewed.
  *How to set:* open Ransom Notes list.

**Suggestions**

* `MassFileModification(f) ∧ ¬ViewedEncryptionMonitor(f) → Suggest(MonitorEncryption(f))`
* `DeletesShadowCopies(f) ∧ ¬ViewedShadowCopyEvents(f) → Suggest(ViewShadowCopyEvents(f))`
* `UploadsLargeVolume(f) ∧ ¬ViewedExfilTimeline(f) → Suggest(ViewExfil(f))`

---

## 14) Anti‑Analysis / Evasion Checks

* **ViewedAntiVMChecks(f)** — Anti‑VM heuristics list viewed.
  *How to set:* open Anti‑Analysis pane.
* **ViewedSleepSkips(f)** — Sleep skipping/timing tricks list viewed.
  *How to set:* open Timing pane.
* **EnabledTimeWarp(f)** — Time acceleration/patch enabled in sandbox.
  *How to set:* toggle time warp.

**Suggestions**

* `ChecksSandboxArtifacts(f) ∧ ¬ViewedAntiVMChecks(f) → Suggest(ViewAntiVM(f))`
* `DelaysExecutionLong(f) ∧ ¬EnabledTimeWarp(f) → Suggest(EnableTimeWarp(f))`

---

## 15) Environment Safety

* **SwitchedToIsolatedNetwork(sbx)** — No‑Internet sandbox profile active.
  *How to set:* sandbox profile change.
* **CreatedSnapshot(sbx, snapId)** — VM snapshot created.
  *How to set:* snapshot made.
* **RestoredSnapshot(sbx, snapId)** — VM reverted.
  *How to set:* restore event.
* **SetReadonlyDirs(sbx, paths)** — Protected folders enforced.
  *How to set:* policy applied.
* **QuarantinedSample(f)** — File moved to quarantine.
  *How to set:* quarantine action.

**Suggestions**

* `InternetOriginCorroborated(f) ∧ ¬SwitchedToIsolatedNetwork(sbx) → Suggest(SwitchToIsolatedNetwork(sbx))`
* `IsHighRiskType(f) ∧ ¬CreatedSnapshot(sbx, any) → Suggest(CreateSnapshot(sbx))`
* `EncryptsManyFiles(f) ∧ ¬SetReadonlyDirs(sbx, any) → Suggest(ProtectUserDirs(sbx))`

---

## 16) Comparative & Baseline Analysis

* **ComparedAgainstBaseline(f)** — Diffed with prior version/sample.
  *How to set:* run baseline diff.
* **ViewedBehaviorDiff(f1,f2)** — Dynamic diff viewed.
  *How to set:* open diff pane.
* **TaggedCluster(f, clusterId)** — Associated with a cluster/campaign.
  *How to set:* tag action.

**Suggestions**

* `SimilarToKnownBad(f) ∧ ¬ComparedAgainstBaseline(f) → Suggest(DiffWithKnownBad(f))`
* `ClusteredC2Campaign(f, any) ∧ ¬ViewedBehaviorDiff(f, any) → Suggest(ViewCampaignDiffs(f))`

---

## 17) Reporting, IOCs & Case Flow

* **ExtractedIOCs(f)** — Domains/IPs/hashes/paths exported.
  *How to set:* IOC extractor run.
* **ViewedIOCList(f)** — IOC list panel opened.
  *How to set:* open IOC list.
* **ExportedIOCs(f, format)** — STIX/CSV/TXT export done.
  *How to set:* export action.
* **GeneratedReport(f, reportId)** — Analyst report generated.
  *How to set:* report tool run.
* **SharedReport(reportId, dest)** — Report shared/post‑processed.
  *How to set:* share event.
* **AddedComment(f)** — Comment added.
  *How to set:* comment posted.
* **AssignedTo(user, f)** — Ownership assigned.
  *How to set:* assignment set.

**Suggestions**

* `IsSuspicious(f) ∧ ¬ExtractedIOCs(f) → Suggest(ExtractIOCs(f))`
* `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any) → Suggest(ExportIOCs(f))`
* `IsMalicious(f) ∧ ¬GeneratedReport(f, any) → Suggest(GenerateReport(f))`

---

## 18) Decision & Guidance UX

* **Accepted(Suggest(Action)))** — User accepted a suggestion.
  *How to set:* on confirm.
* **Dismissed(Suggest(Action)))** — User dismissed suggestion.
  *How to set:* on dismiss.
* **Snoozed(Suggest(Action), Δt)** — Snoozed for Δt.
  *How to set:* snooze.
* **Explained(Action, textId)** — Explanation tooltip viewed.
  *How to set:* info icon clicked.
* **LearnedHowTo(Action)** — User opened a how‑to for the action.
  *How to set:* “Learn more”.

**Suggestions management**

* `Dismissed(Suggest(X)) → Suppress(Suggest(X), 1h)`
* `Snoozed(Suggest(X), Δt) → Suppress(Suggest(X), Δt)`

---

## 19) Cross‑cutting Coverage Predicates (quick “have I looked at…?”)

Use these as **coverage gates** for suggestions:

* **StaticReviewed(f)** — `ViewedHeaders ∧ ViewedSections ∧ ViewedStrings` (composite).
  *How to set:* auto when all subfacts set.
* **DynamicReviewed(f)** — `ViewedProcessTree ∧ ViewedNetworkBehavior ∧ ViewedFileSystemActivity`.
* **PersistenceReviewed(f)** — `ViewedRunKeys ∨ ViewedScheduledTasks ∨ ViewedServices ∨ ViewedWmiSubscriptions`.
* **MacroReviewed(f)** — `ViewedMacros ∧ (DecompiledVBA ∨ ViewedXlmSheets)`.
* **ReputationReviewed(f)** — `ComputedHashes ∧ QueriedThreatIntel`.
* **ProvenanceReviewed(f)** — `ViewedMOTW ∨ ViewedOrigin`.

**Suggestion template**

* `RelevantIndicator(f, domain) ∧ ¬CoverageDomainReviewed(f, domain) → Suggest(OpenDomainPanel(f, domain))`
  *Use domain ∈ {Static, Dynamic, Persistence, Macro, Reputation, Provenance}.*

---

## 20) “Suggest” Library (ready‑to‑wire actions)

> Each suggestion should carry a message via `Explain(Suggest(Action), "...")`.

* **Suggest(ComputeHashes(f))** — *“Compute hashes to enable intel lookups & dedup.”*
* **Suggest(QueryThreatIntel(f))** — *“Check reputation across intel sources.”*
* **Suggest(ViewSignature(f))** — *“Inspect digital signature validity.”*
* **Suggest(ViewMOTW(f))** — *“Review Internet origin details.”*
* **Suggest(ExtractUrls(f))** — *“Extract URLs for pivot & blocking.”*
* **Suggest(DecodeBase64(f)) / Suggest(DecodeHex(f))** — *“Decode embedded blobs.”*
* **Suggest(CarveEmbedded(f))** — *“Carve embedded archive/executable.”*
* **Suggest(ViewMacros(f))** — *“Macros present. Analyze source and auto‑execs.”*
* **Suggest(DeobfuscateVBA(f))** — *“Macro obfuscation detected. Deobfuscate now?”*
* **Suggest(ViewExternalTemplates(f))** — *“Inspect remote template references.”*
* **Suggest(BeautifyScript(f))** — *“Beautify/minified script for readability.”*
* **Suggest(ViewImports(f)) / Suggest(ViewResources(f)) / Suggest(IdentifyPacker(f))**
* **Suggest(LaunchSandbox(f))** — *“Detonate safely to collect behavior.”*
* **Suggest(ViewNetwork(f)) / Suggest(ViewFileWrites(f)) / Suggest(ViewRegistryChanges(f)) / Suggest(ViewProcessTree(f))**
* **Suggest(ViewPersistence(f)) / Suggest(ViewUac(f))**
* **Suggest(ViewTlsCertificates(f)) / Suggest(ViewDnsQueries(f))**
* **Suggest(MonitorEncryption(f)) / Suggest(ViewShadowCopyEvents(f)) / Suggest(ViewExfil(f))**
* **Suggest(SwitchToIsolatedNetwork(sbx)) / Suggest(CreateSnapshot(sbx)) / Suggest(ProtectUserDirs(sbx))**
* **Suggest(ExtractIOCs(f)) / Suggest(ExportIOCs(f)) / Suggest(GenerateReport(f))**
* **Suggest(OpenInSafeView(f)) / Suggest(Pin(f)) / Suggest(DiffWithKnownBad(f)) / Suggest(ViewCampaignDiffs(f))**

---

## 21) Example Inference Rules (mix of your earlier signals + user‑action coverage)

> Use these as templates; they all produce a `Suggest(…)` with a short explanation.

### Office / Macros

1. `IsWord(f) ∧ HasMacros(f) ∧ ¬ViewedMacros(f) → Suggest(ViewMacros(f))`
   *“This file contains macros. Open the Macro Viewer?”*
2. `HasMacroObfuscation(f) ∧ ¬DeobfuscatedVBA(f) → Suggest(DeobfuscateVBA(f))`
   *“Obfuscation detected. Attempt automated deobfuscation?”*
3. `ContainsExternalTemplateRef(f) ∧ ¬ViewedExternalTemplateRels(f) → Suggest(ViewExternalTemplates(f))`
   *“External template reference found. Inspect for remote code load?”*

### Strings/Blobs

4. `ContainsBase64Blobs(f) ∧ ¬DecodedBase64Blobs(f) → Suggest(DecodeBase64(f))`
5. `ContainsUrl(f) ∧ ¬ExtractedUrls(f) → Suggest(ExtractUrls(f))`

### PE/Static

6. `IsPe(f) ∧ HasHighEntropy(f) ∧ ¬RanPackerId(f) → Suggest(IdentifyPacker(f))`
7. `IsPe(f) ∧ ContainsEmbeddedExecutable(f) ∧ ¬ViewedResources(f) → Suggest(ViewResources(f))`

### Dynamic

8. `TriesToAccessTheInternet(f) ∧ ¬ViewedNetworkBehavior(f) → Suggest(ViewNetwork(f))`
9. `DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f) → Suggest(ViewProcessTree(f))`
10. `CreatesRunKey(f) ∧ ¬ViewedRegistryActivity(f) → Suggest(ViewRegistryChanges(f))`

### Persistence/Privilege

11. `PersistenceIndicatorsPresent(f) ∧ ¬PersistenceReviewed(f) → Suggest(ViewPersistence(f))`
12. `RequestsUacElevation(f) ∧ ¬ViewedUacEvents(f) → Suggest(ViewUac(f))`

### Reputation/Provenance

13. `¬ComputedHashes(f) → Suggest(ComputeHashes(f))`
14. `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any) → Suggest(QueryThreatIntel(f))`
15. `MarkOfTheWeb(f) ∧ ¬ViewedMOTW(f) → Suggest(ViewMOTW(f))`

### Safety

16. `IsActiveContentCapable(f) ∧ ¬OpenedSafely(f) → Suggest(OpenInSafeView(f))`
17. `InternetOriginCorroborated(f) ∧ ¬SwitchedToIsolatedNetwork(sbx) → Suggest(SwitchToIsolatedNetwork(sbx))`

### Ransomware/Exfil

18. `EncryptsManyFiles(f) ∧ ¬ViewedEncryptionMonitor(f) → Suggest(MonitorEncryption(f))`
19. `DeletesShadowCopies(f) ∧ ¬ViewedShadowCopyEvents(f) → Suggest(ViewShadowCopyEvents(f))`
20. `UploadsLargeVolume(f) ∧ ¬ViewedExfilTimeline(f) → Suggest(ViewExfil(f))`

### Reporting/IOCs

21. `IsSuspicious(f) ∧ ¬ExtractedIOCs(f) → Suggest(ExtractIOCs(f))`
22. `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any) → Suggest(ExportIOCs(f))`
23. `IsMalicious(f) ∧ ¬GeneratedReport(f, any) → Suggest(GenerateReport(f))`

### Campaign/Baseline

24. `SimilarToKnownBad(f) ∧ ¬ComparedAgainstBaseline(f) → Suggest(DiffWithKnownBad(f))`
25. `ClusteredC2Campaign(f, any) ∧ ¬ViewedBehaviorDiff(f, any) → Suggest(ViewCampaignDiffs(f))`

---

## 22) Implementation Hints (wiring)

* **Mark ‘Viewed…’** when the user opens the pane **and** either (a) stays > `dwell_ms` or (b) clicks a control inside it.
* **Emit suggestions once** unless `Snoozed` expires; use `Dismissed(Suggest(X))` to suppress repeats.
* **Attach explanations** via `Explain(Suggest(X), "message")` and optionally `Severity(Suggest(X), info|warn|high)`.
* **Composite coverage** (e.g., `PersistenceReviewed`) should auto‑flip when all subfacts are met.
* **Guard risky suggestions** (sandbox detonation, deobfuscation) with environment checks: only propose if `SwitchedToIsolatedNetwork` or `OpenedSafely`.

---

## Inference rules

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

## A) FILE‑ONLY TRIGGERS → SUGGESTIONS

> Fire even before the user looks anywhere (good for “first steps”).

### A1. Office / Word / Excel / PPT

* **\[F-001]** `IsWord(f) ∧ HasMacros(f)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros present. Open the Macro Viewer?", cooldown: 30m, tags:\[office,macro]}
* **\[F-002]** `IsWord(f) ∧ HasMacroObfuscation(f)` → `Suggest(DeobfuscateVBA(f))`
  {severity: high, message: "Obfuscation detected. Deobfuscate VBA now?", cooldown: 30m, tags:\[office,macro]}
* **\[F-003]** `IsWord(f) ∧ ContainsExternalTemplateRef(f)` → `Suggest(ViewExternalTemplates(f))`
  {severity: warn, message: "Document references external template(s). Inspect RELs?", cooldown: 30m, tags:\[office,template]}
* **\[F-004]** `IsExcel(f) ∧ HasXlm4Macro(f)` → `Suggest(ViewXlmSheets(f))`
  {severity: high, message: "Excel 4.0 macro sheet present. Review it?", cooldown: 30m, tags:\[excel,xlm]}
* **\[F-005]** `IsExcel(f) ∧ HasHiddenSheets(f)` → `Suggest(ViewHiddenSheets(f))`
  {severity: warn, message: "Hidden/VeryHidden sheets found. Show list?", cooldown: 30m, tags:\[excel,stealth]}
* **\[F-006]** `IsPowerPoint(f) ∧ PptHasActionButtonMacro(f)` → `Suggest(ViewPptActions(f))`
  {severity: warn, message: "Action buttons invoke code. Inspect?", cooldown: 30m, tags:\[ppt,macro]}

### A2. PDF / RTF / OLE

* **\[F-010]** `IsPdf(f) ∧ PdfHasJavaScript(f)` → `Suggest(ViewPdfJavaScript(f))`
  {severity: high, message: "Embedded JavaScript present. Inspect code?", cooldown: 30m, tags:\[pdf,script]}
* **\[F-011]** `IsPdf(f) ∧ PdfHasOpenAction(f)` → `Suggest(ViewPdfObjects(f))`
  {severity: high, message: "Auto‑action triggers on open. Inspect object tree?", cooldown: 30m, tags:\[pdf,autorun]}
* **\[F-012]** `IsRtf(f) ∧ ContainsKnownExploitArtifacts(f)` → `Suggest(ViewRtfControls(f))`
  {severity: high, message: "Exploitation artifacts in RTF. Review control words?", cooldown: 30m, tags:\[rtf,exploit]}
* **\[F-013]** `AbusesEquationEditor(f)` → `Suggest(ViewOleObjects(f))`
  {severity: high, message: "Legacy Equation Editor usage. Inspect OLE objects?", cooldown: 30m, tags:\[office,ole]}

### A3. Script families (PS1/JS/VBS/HTA)

* **\[F-020]** `IsScript(f) ∧ HasObfuscatedStrings(f)` → `Suggest(BeautifyScript(f))`
  {severity: high, message: "Obfuscated script. Beautify for review?", cooldown: 30m, tags:\[script,obfuscation]}
* **\[F-021]** `IsPowerShellScript(f) ∧ ContainsDownloaderCode(f)` → `Suggest(ViewDynamicEval(f))`
  {severity: high, message: "Downloader patterns found. Inspect dynamic invocation?", cooldown: 30m, tags:\[ps1,downloader]}
* **\[F-022]** `IsHTA(f) ∧ ContainsUrl(f)` → `Suggest(ViewScriptSource(f))`
  {severity: warn, message: "HTA with URLs. Open source view?", cooldown: 30m, tags:\[hta]}

### A4. PE/ELF/Mach‑O (static)

* **\[F-030]** `IsPe(f) ∧ HasHighEntropy(f)` → `Suggest(IdentifyPacker(f))`
  {severity: warn, message: "High entropy indicates packing. Identify packer?", cooldown: 30m, tags:\[pe,packing]}
* **\[F-031]** `IsPe(f) ∧ ContainsEmbeddedExecutable(f)` → `Suggest(ViewResources(f))`
  {severity: warn, message: "Embedded payloads detected. Inspect resources?", cooldown: 30m, tags:\[pe,resources]}
* **\[F-032]** `IsPe(f) ∧ ¬IsSigned(f)` → `Suggest(ViewSignature(f))`
  {severity: info, message: "Binary is unsigned. Review signature panel for certainty?", cooldown: 30m, tags:\[pe,signing]}
* **\[F-033]** `IsPe(f) ∧ IsSigned(f) ∧ ¬SignatureValid(f)` → `Suggest(ViewSignatureProblems(f))`
  {severity: high, message: "Invalid/revoked signature. Inspect chain & timestamp?", cooldown: 30m, tags:\[pe,signing]}

### A5. Archives / Installers / Shortcuts

* **\[F-040]** `IsArchive(f) ∧ ArchiveIsPasswordProtected(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Password‑protected archive. Safe‑extract to sandbox?", cooldown: 30m, tags:\[archive,safety]}
* **\[F-041]** `IsArchive(f) ∧ ArchiveContainsExecutable(f)` → `Suggest(ViewArchiveManifest(f))`
  {severity: warn, message: "Executable(s) inside archive. Review manifest?", cooldown: 30m, tags:\[archive]}
* **\[F-042]** `IsInstaller(f) ∧ MsiRunsCustomAction(f)` → `Suggest(ViewMsiCustomActions(f))`
  {severity: warn, message: "MSI CustomAction(s) found. Inspect?", cooldown: 30m, tags:\[msi]}
* **\[F-043]** `IsLnk(f) ∧ IsShortcutAbuseCandidate(f)` → `Suggest(ViewLnkTarget(f))`
  {severity: high, message: "LNK launches external content. Review target & args?", cooldown: 30m, tags:\[lnk]}

### A6. Reputation / Provenance

* **\[F-050]** `MarkOfTheWeb(f)` → `Suggest(ViewMOTW(f))`
  {severity: info, message: "Internet‑origin marker present. Inspect source zone?", cooldown: 30m, tags:\[provenance]}
* **\[F-051]** `HashInThreatIntel(f)` → `Suggest(ViewThreatIntelHits(f))`
  {severity: critical, message: "Known bad hash in intel. Review details immediately?", cooldown: 5m, tags:\[intel]}
* **\[F-052]** `IsSigned(f) ∧ SignatureValid(f) ∧ SignedByKnownVendor(f)` → `Suggest(RecordPublisherTrust(f))`
  {severity: info, message: "Trusted publisher signature. Record as benign candidate?", cooldown: 1h, tags:\[trust]}

---

## B) USER‑ONLY TRIGGERS → SUGGESTIONS

> Coach the analyst based on **coverage gaps** and **workflow hygiene**.

### B1. Coverage reminders

* **\[U-100]** `Opened(f) ∧ ¬ViewedHashes(f)` → `Suggest(ComputeHashes(f))`
  {severity: info, message: "Compute hashes for correlation & TI lookups?", cooldown: 30m, tags:\[workflow,hash]}
* **\[U-101]** `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any)` → `Suggest(QueryThreatIntel(f))`
  {severity: info, message: "Check reputation across intel sources?", cooldown: 30m, tags:\[workflow,intel]}
* **\[U-102]** `Opened(f) ∧ ¬ViewedStrings(f)` → `Suggest(ViewStrings(f))`
  {severity: info, message: "Review strings for URLs, IOCs and clues?", cooldown: 45m, tags:\[strings]}
* **\[U-103]** `Opened(f) ∧ ¬StaticReviewed(f)` → `Suggest(OpenStaticChecklist(f))`
  {severity: info, message: "Finish static triage checklist?", cooldown: 45m, tags:\[checklist]}

### B2. Dynamic workflow

* **\[U-110]** `LaunchedInSandbox(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: warn, message: "Sandbox run active. Review process tree?", cooldown: 15m, tags:\[dynamic]}
* **\[U-111]** `LaunchedInSandbox(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: warn, message: "Network telemetry available. Check connections?", cooldown: 15m, tags:\[dynamic,network]}
* **\[U-112]** `LaunchedInSandbox(f) ∧ ¬ViewedFileSystemActivity(f)` → `Suggest(ViewFileWrites(f))`
  {severity: info, message: "Review filesystem changes?", cooldown: 15m, tags:\[dynamic,fs]}
* **\[U-113]** `LaunchedInSandbox(f) ∧ ¬ViewedRegistryActivity(f)` → `Suggest(ViewRegistryChanges(f))`
  {severity: info, message: "Review registry changes?", cooldown: 15m, tags:\[dynamic,registry]}

### B3. Safety & discipline

* **\[U-120]** `Opened(f) ∧ IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Use protected view to avoid executing active content?", cooldown: 30m, tags:\[safety]}
* **\[U-121]** `Opened(f) ∧ MarkOfTheWeb(f) ∧ ¬SwitchedToIsolatedNetwork(sbx)` → `Suggest(SwitchToIsolatedNetwork(sbx))`
  {severity: high, message: "Switch sandbox to no‑Internet profile?", cooldown: 30m, tags:\[sandbox]}
* **\[U-122]** `Opened(f) ∧ ¬CreatedSnapshot(sbx, any)` → `Suggest(CreateSnapshot(sbx))`
  {severity: info, message: "Create VM snapshot before detonation?", cooldown: 1h, tags:\[safety,snapshot]}

### B4. Case hygiene

* **\[U-130]** `IsSuspicious(f) ∧ ¬AddedToCase(f, any)` → `Suggest(AddToCase(f))`
  {severity: info, message: "Track this file in your case?", cooldown: 1h, tags:\[case]}
* **\[U-131]** `IsMalicious(f) ∧ ¬GeneratedReport(f, any)` → `Suggest(GenerateReport(f))`
  {severity: high, message: "Generate a report with observed IOCs?", cooldown: 1h, tags:\[report]}
* **\[U-132]** `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any)` → `Suggest(ExportIOCs(f))`
  {severity: info, message: "Export IOCs (CSV/STIX) for sharing?", cooldown: 1h, tags:\[ioc]}
* **\[U-133]** `AddedToCase(f, caseId) ∧ ¬AssignedTo(self, f)` → `Suggest(AssignToSelf(f))`
  {severity: info, message: "Assign ownership to yourself?", cooldown: 1h, tags:\[case,ownership]}

---

## C) MIXED TRIGGERS (FILE + USER) → SUGGESTIONS

> “Do X because Y is present **and** you haven’t looked at Z.”

### C1. Office / Macros (deep)

* **\[M-200]** `IsWord(f) ∧ HasMacros(f) ∧ ¬ViewedMacros(f)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros present. Open Macro Viewer?", cooldown: 30m, tags:\[office,macro]}
* **\[M-201]** `HasMacroObfuscation(f) ∧ ¬DeobfuscatedVBA(f)` → `Suggest(DeobfuscateVBA(f))`
  {severity: high, message: "Obfuscated macros found. Deobfuscate now?", cooldown: 30m, tags:\[macro,obfuscation]}
* **\[M-202]** `HasSuspiciousMacroFunctionCalls(f) ∧ ¬ViewedSuspiciousCalls(f)` → `Suggest(ViewSuspiciousCalls(f))`
  {severity: high, message: "Suspicious macro APIs detected. Review call list?", cooldown: 30m}
* **\[M-203]** `ContainsExternalTemplateRef(f) ∧ ¬ViewedExternalTemplateRels(f)` → `Suggest(ViewExternalTemplates(f))`
  {severity: warn, message: "Remote template reference. Inspect RELs?", cooldown: 30m}
* **\[M-204]** `HasMacroPersistence(f) ∧ ¬PersistenceReviewed(f)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "Macro attempts persistence. Review startup/task/service writes?", cooldown: 30m}

### C2. Strings / Blobs / Carving

* **\[M-210]** `ContainsBase64Blobs(f) ∧ ¬DecodedBase64Blobs(f)` → `Suggest(DecodeBase64(f))`
  {severity: warn, message: "Base64 blobs detected. Decode for payloads?", cooldown: 30m}
* **\[M-211]** `ContainsHexBlobs(f) ∧ ¬DecodedHexBlobs(f)` → `Suggest(DecodeHex(f))`
  {severity: info, message: "Hex blobs present. Decode now?", cooldown: 30m}
* **\[M-212]** `ContainsUrl(f) ∧ ¬ExtractedUrls(f)` → `Suggest(ExtractUrls(f))`
  {severity: info, message: "Extract URLs for pivoting & blocking?", cooldown: 30m}
* **\[M-213]** `ContainsEmbeddedArchive(f) ∧ ¬CarvedEmbeddedFiles(f)` → `Suggest(CarveEmbedded(f))`
  {severity: warn, message: "Embedded archive(s) found. Carve safely?", cooldown: 30m}
* **\[M-214]** `ContainsEmbeddedExecutable(f) ∧ ¬CarvedEmbeddedFiles(f)` → `Suggest(CarveEmbedded(f))`
  {severity: high, message: "Embedded executable detected. Extract for triage?", cooldown: 30m}

### C3. PE / Native (static+user)

* **\[M-220]** `IsPe(f) ∧ ¬ViewedImports(f)` → `Suggest(ViewImports(f))`
  {severity: info, message: "Review imported APIs for intent?", cooldown: 45m}
* **\[M-221]** `IsPe(f) ∧ HasHighEntropy(f) ∧ ¬RanPackerId(f)` → `Suggest(IdentifyPacker(f))`
  {severity: warn, message: "Likely packed. Identify packer?", cooldown: 45m}
* **\[M-222]** `IsPe(f) ∧ ¬ViewedResources(f) ∧ ContainsEmbeddedScript(f)` → `Suggest(ViewResources(f))`
  {severity: warn, message: "Script content embedded. Inspect resources?", cooldown: 45m}
* **\[M-223]** `IsPe(f) ∧ ¬ViewedOverlay(f) ∧ HasOverlayData(f)` → `Suggest(ViewOverlay(f))`
  {severity: info, message: "Overlay data present. Inspect trailing bytes?", cooldown: 45m}

### C4. Dynamic / Behavior

* **\[M-230]** `TriesToAccessTheInternet(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "Outbound connections observed. Review endpoints?", cooldown: 20m}
* **\[M-231]** `BeaconingPattern(f) ∧ ¬ResolvedDomains(f)` → `Suggest(ViewDnsQueries(f))`
  {severity: high, message: "Beaconing detected. Review DNS queries/domains?", cooldown: 20m}
* **\[M-232]** `UsesHTTPSRequests(f) ∧ UsesSelfSignedTls(f) ∧ ¬ViewedTlsCertificates(f)` → `Suggest(ViewTlsCertificates(f))`
  {severity: high, message: "Self‑signed/invalid TLS. Inspect certificate chain?", cooldown: 20m}
* **\[M-233]** `WritesToTempExecutable(f) ∧ ¬ViewedFileSystemActivity(f)` → `Suggest(ViewFileWrites(f))`
  {severity: high, message: "New executable(s) in temp. Review drops?", cooldown: 20m}
* **\[M-234]** `DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "Drop‑and‑run sequence observed. Open process tree?", cooldown: 20m}
* **\[M-235]** `CreatesRunKey(f) ∧ ¬ViewedRegistryActivity(f)` → `Suggest(ViewRegistryChanges(f))`
  {severity: high, message: "Startup persistence detected. Inspect registry changes?", cooldown: 20m}

### C5. Persistence / Privilege

* **\[M-240]** `PersistenceIndicatorsPresent(f) ∧ ¬PersistenceReviewed(f)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "Persistence artifacts found. Review them now?", cooldown: 30m}
* **\[M-241]** `RequestsUacElevation(f) ∧ ¬ViewedUacEvents(f)` → `Suggest(ViewUac(f))`
  {severity: warn, message: "UAC prompt/elevation attempt. Inspect event details?", cooldown: 30m}
* **\[M-242]** `AcquiresSeDebugPrivilege(f) ∧ ¬ViewedTokenPrivileges(f)` → `Suggest(ViewTokenPrivileges(f))`
  {severity: high, message: "Debug privilege acquired. Review token changes?", cooldown: 30m}

### C6. Ransomware / Destruction

* **\[M-250]** `MassFileModification(f) ∧ ¬ViewedEncryptionMonitor(f)` → `Suggest(MonitorEncryption(f))`
  {severity: critical, message: "Rapid file modifications. Start encryption monitor?", cooldown: 10m}
* **\[M-251]** `DeletesShadowCopies(f) ∧ ¬ViewedShadowCopyEvents(f)` → `Suggest(ViewShadowCopyEvents(f))`
  {severity: high, message: "VSS deletion observed. Inspect events?", cooldown: 20m}
* **\[M-252]** `DropsRansomNote(f) ∧ ¬ViewedRansomNotes(f)` → `Suggest(ViewRansomNotes(f))`
  {severity: high, message: "Ransom note artifacts dropped. Open list?", cooldown: 20m}

### C7. Exfiltration / Espionage

* **\[M-260]** `ReadsManyDocs(f) ∧ ¬ViewedExfilTimeline(f)` → `Suggest(ViewExfil(f))`
  {severity: high, message: "Mass document reads. Check exfil timeline?", cooldown: 20m}
* **\[M-261]** `CompressesBeforeUpload(f) ∧ ¬ViewedArchiveManifest(f)` → `Suggest(ViewArchiveManifest(f))`
  {severity: warn, message: "Local staging via archive. Inspect staged files?", cooldown: 20m}
* **\[M-262]** `UploadsLargeVolume(f) ∧ ¬CapturedPcap(f)` → `Suggest(StartCapturePcap(f))`
  {severity: high, message: "Large outbound traffic. Capture PCAP now?", cooldown: 15m}

### C8. Anti‑analysis / Evasion

* **\[M-270]** `ChecksSandboxArtifacts(f) ∧ ¬ViewedAntiVMChecks(f)` → `Suggest(ViewAntiVM(f))`
  {severity: warn, message: "Anti‑VM checks observed. Review heuristics?", cooldown: 30m}
* **\[M-271]** `DelaysExecutionLong(f) ∧ ¬EnabledTimeWarp(f)` → `Suggest(EnableTimeWarp(f))`
  {severity: info, message: "Long sleeps observed. Enable time warp?", cooldown: 30m}
* **\[M-272]** `UsesParentPidSpoofing(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "PPID spoofing suspected. Inspect lineage?", cooldown: 20m}

### C9. Archives / Installers / LNK (mixed)

* **\[M-280]** `IsArchive(f) ∧ ArchiveIsPasswordProtected(f) ∧ ¬ExtractedArchiveSafely(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Password‑protected archive. Extract to sandbox?", cooldown: 30m}
* **\[M-281]** `IsInstaller(f) ∧ MsiRunsCustomAction(f) ∧ ¬ViewedMsiCustomActions(f)` → `Suggest(ViewMsiCustomActions(f))`
  {severity: warn, message: "MSI CustomAction(s) present. Inspect?", cooldown: 30m}
* **\[M-282]** `IsLnk(f) ∧ IsShortcutAbuseCandidate(f) ∧ ¬ViewedLnkTarget(f)` → `Suggest(ViewLnkTarget(f))`
  {severity: high, message: "Suspicious shortcut target. Review args & path?", cooldown: 30m}

### C10. Provenance / Reputation / Reporting

* **\[M-290]** `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any) ∧ (ContainsUrl(f) ∨ TriesToAccessTheInternet(f))` → `Suggest(QueryThreatIntel(f))`
  {severity: info, message: "Reputation check likely useful here. Query TI?", cooldown: 30m}
* **\[M-291]** `InternetOriginCorroborated(f) ∧ IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Internet‑delivered active content. Use safe view?", cooldown: 30m}
* **\[M-292]** `IsSuspicious(f) ∧ ¬ExtractedIOCs(f)` → `Suggest(ExtractIOCs(f))`
  {severity: high, message: "Extract IOCs to pivot and contain?", cooldown: 45m}
* **\[M-293]** `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any)` → `Suggest(ExportIOCs(f))`
  {severity: info, message: "Export IOCs (CSV/STIX) for sharing?", cooldown: 1h}
* **\[M-294]** `IsMalicious(f) ∧ ¬GeneratedReport(f, any)` → `Suggest(GenerateReport(f))`
  {severity: high, message: "Generate a concise report with findings?", cooldown: 1h}

---

## D) TIME‑WINDOWED PLAYBOOKS (sequenced coaching)

* **\[P-300]** `IsWord(f) ∧ HasMacros(f) ∧ UserEnabledMacros(u,f) ∧ ¬ViewedMacros(f) ∧ Within(5m)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros executed recently. Inspect source now.", cooldown: 15m}
* **\[P-301]** `WritesToTempExecutable(f) ∧ DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f) ∧ Within(3m)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "Drop‑and‑run chain just occurred. Open process graph.", cooldown: 15m}
* **\[P-302]** `DownloadsFromInternet(f) ∧ ¬ViewedNetworkBehavior(f) ∧ Within(10m)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "Recent download observed. Review network flows.", cooldown: 20m}
* **\[P-303]** `CreatesRunKey(f) ∧ ¬PersistenceReviewed(f) ∧ Within(10m)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "New persistence. Review startup artifacts.", cooldown: 20m}
* **\[P-304]** `BeaconingPattern(f) ∧ ¬CapturedPcap(f) ∧ Within(15m)` → `Suggest(StartCapturePcap(f))`
  {severity: high, message: "Beaconing ongoing. Capture PCAP for C2 analysis.", cooldown: 15m}

---

## E) SAFETY & ISOLATION GUARDRAILS

> Only propose potentially risky actions when the environment is safe.

* **\[S-400]** `IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Use protected view to avoid code execution.", cooldown: 30m}
* **\[S-401]** `TriesToAccessTheInternet(f) ∧ ¬SwitchedToIsolatedNetwork(sbx)` → `Suggest(SwitchToIsolatedNetwork(sbx))`
  {severity: high, message: "Switch to isolated/no‑Internet sandbox.", cooldown: 30m}
* **\[S-402]** `EncryptsManyFiles(f) ∧ ¬SetReadonlyDirs(sbx, any)` → `Suggest(ProtectUserDirs(sbx))`
  {severity: critical, message: "Protect user directories (read‑only policy).", cooldown: 10m}
* **\[S-403]** `Opened(f) ∧ ¬CreatedSnapshot(sbx, any)` → `Suggest(CreateSnapshot(sbx))`
  {severity: info, message: "Create VM snapshot before detonation.", cooldown: 1h}

---

## F) PRIORITIZATION, DEDUP & META‑SUGGESTIONS

> Manage suggestion noise and coach next best action.

* **\[X-500]** `Dismissed(Suggest(X))` → `Suppress(Suggest(X), 1h)`
  {severity: info, message: "Muted for 1 hour.", cooldown: 0}
* **\[X-501]** `Snoozed(Suggest(X), Δt)` → `Suppress(Suggest(X), Δt)`
  {severity: info, message: "Snoozed.", cooldown: 0}
* **\[X-502]** `IsMalicious(f) ∧ MultipleSuggestionsPending(f) → PrioritizeSuggestions(f, order=["ViewProcessTree","ViewNetwork","ViewPersistence","ExtractIOCs","GenerateReport"])`
  {severity: high, message: "Prioritizing critical next steps.", cooldown: 10m}
* **\[X-503]** `LikelyBenign(f) ∧ Suggest(LaunchSandbox(f))` → `DowngradeSeverity(Suggest(LaunchSandbox(f)))`
  {severity: info, message: "Sandbox detonation optional for benign‑leaning sample.", cooldown: 1h}

---

## G) CAMPAIGN / CORRELATION COACHING

* **\[C-600]** `ClusteredC2Campaign(f, any) ∧ ¬ViewedBehaviorDiff(f, any)` → `Suggest(ViewCampaignDiffs(f))`
  {severity: info, message: "Compare behavior across cluster samples.", cooldown: 1h}
* **\[C-601]** `SimilarToKnownBad(f) ∧ ¬ComparedAgainstBaseline(f)` → `Suggest(DiffWithKnownBad(f))`
  {severity: info, message: "Diff against prior known‑bad to speed triage.", cooldown: 1h}
* **\[C-602]** `HashInThreatIntel(f) ∧ ¬AddedToCase(f, any)` → `Suggest(AddToCase(f))`
  {severity: high, message: "Track intel‑matched sample in your case.", cooldown: 1h}

---

## H) EMAIL / PHISHING CONTEXT

* **\[E-700]** `SourceIsEmailAttachment(f) ∧ HasSuspiciousAttachment(f) ∧ ¬ViewedOrigin(f)` → `Suggest(ViewOrigin(f))`
  {severity: warn, message: "Check message headers and sender context.", cooldown: 45m}
* **\[E-701]** `SourceIsEmailAttachment(f) ∧ MarkOfTheWeb(f) ∧ ¬ViewedMOTW(f)` → `Suggest(ViewMOTW(f))`
  {severity: info, message: "Attachment marked Internet‑origin. Review zone data.", cooldown: 45m}
* **\[E-702]** `IsPhishingEmail(f) ∧ LinksToCredentialHarvestingSite(f) ∧ ¬ExtractedIOCs(f)` → `Suggest(ExtractIOCs(f))`
  {severity: high, message: "Extract URLs/domains for blocking.", cooldown: 45m}

---

## I) ARCHIVE / INSTALLER PLAYBOOKS

* **\[A-800]** `IsArchive(f) ∧ ArchiveDoubleExtensionMembers(f) ∧ ¬ViewedDoubleExtensions(f)` → `Suggest(ViewDoubleExtensions(f))`
  {severity: warn, message: "Suspicious member names (.pdf.exe). Review.", cooldown: 45m}
* **\[A-801]** `IsArchive(f) ∧ ArchiveContainsScript(f) ∧ ¬ExtractedArchiveSafely(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Scripts inside. Safe‑extract to sandbox.", cooldown: 45m}
* **\[A-802]** `IsInstaller(f) ∧ (BinarySpawnsScripting(f) ∨ DownloadsFromInternet(f)) ∧ ¬LaunchedInSandbox(f)` → `Suggest(LaunchSandbox(f))`
  {severity: high, message: "Installer exhibits risky behavior. Detonate safely.", cooldown: 30m}

---

## J) LATERAL MOVEMENT / CREDENTIAL ACCESS

* **\[L-900]** `UsesWmiForExec(f) ∧ ¬ViewedWmiSubscriptions(f)` → `Suggest(ViewWmiSubscriptions(f))`
  {severity: high, message: "WMI activity. Inspect subscriptions/consumers.", cooldown: 30m}
* **\[L-901]** `UsesSmb(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "SMB connections observed. Review peers.", cooldown: 30m}
* **\[L-902]** `ReadsLsassMemory(f) ∧ ¬ViewedTokenPrivileges(f)` → `Suggest(ViewTokenPrivileges(f))`
  {severity: critical, message: "Credential theft indicator. Review token scope.", cooldown: 15m}
* **\[L-903]** `UsesPsExecLike(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "Remote exec pattern. Inspect process lineage.", cooldown: 30m}

---

## K) REPORTING & REMEDIATION NUDGES

* **\[R-1000]** `IsSuspicious(f) ∧ ExtractedIOCs(f) ∧ ¬SharedReport(any, any)` → `Suggest(ShareFindings(f))`
  {severity: info, message: "Share IOCs & summary with response team.", cooldown: 2h}
* **\[R-1001]** `IsMalicious(f) ∧ ¬QuarantinedSample(f)` → `Suggest(QuarantineSample(f))`
  {severity: high, message: "Quarantine sample to prevent accidental execution.", cooldown: 1h}
* **\[R-1002]** `StrongPublisherTrust(f) ∧ KnownGoodHash(f) ∧ ¬WhitelistedInOrg(f)` → `Suggest(WhitelistInOrg(f))`
  {severity: info, message: "Add to organizational allow‑list (after review).", cooldown: 4h}

---

## L) “COVERAGE GATES” (auto‑composite suggestions)

> Use composite predicates to prompt missing parts of an investigation domain.

* **\[G-1100]** `¬ReputationReviewed(f)` → `Suggest(OpenReputationChecklist(f))`
  {severity: info, message: "Reputation not reviewed. Hashes + TI + signer.", cooldown: 45m}
* **\[G-1101]** `¬StaticReviewed(f)` → `Suggest(OpenStaticChecklist(f))`
  {severity: info, message: "Static triage incomplete. Headers/sections/strings.", cooldown: 45m}
* **\[G-1102]** `LaunchedInSandbox(f) ∧ ¬DynamicReviewed(f)` → `Suggest(OpenDynamicChecklist(f))`
  {severity: info, message: "Dynamic triage incomplete. Proc/Net/FS/Reg.", cooldown: 30m}
* **\[G-1103]** `MacroReviewed(f) ∧ ¬PersistenceReviewed(f) ∧ (HasMacroPersistence(f) ∨ CreatesRunKey(f))` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "Persistence present but not reviewed.", cooldown: 30m}

---

## Implementation notes

* **Where to fire**: evaluate rules on (a) file load, (b) predicate change (new telemetry), (c) panel open/close, and (d) timed intervals for `Within(T)` windows.
* **How to display**: couple `Suggest(Action)` with `Explain(…, message)` and a button. Add `severity` as color/priority.
* **Noise control**: group similar suggestions; respect `Dismissed` and `Snoozed`; never re‑suggest within `cooldown`.
* **Safety checks**: automatically prepend guards (e.g., only propose `LaunchSandbox` if sandbox exists; only propose `SafeExtract` if a safe path is configured).

---
