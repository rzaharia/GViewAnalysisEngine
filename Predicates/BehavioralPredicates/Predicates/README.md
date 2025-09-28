# # GView Analysis Engine - Behavioral predicates

Here is the entire list of the predicates in a readable way along with some suggestions of some inference rules.

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

## 19) Cross-cutting Coverage Predicates (quick “have I looked at…?”)

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
