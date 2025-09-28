# GView Analysis engine - Inference rules

## Suggestions

### A1. Office / Word / Excel / PPT

* **\[F-0001]** `IsWord(f) ∧ HasMacros(f)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros present. Open the Macro Viewer?", cooldown: 30m, tags:\[office,macro]}
* **\[F-0002]** `IsWord(f) ∧ HasMacroObfuscation(f)` → `Suggest(DeobfuscateVBA(f))`
  {severity: high, message: "Obfuscation detected. Deobfuscate VBA now?", cooldown: 30m, tags:\[office,macro]}
* **\[F-0003]** `IsWord(f) ∧ ContainsExternalTemplateRef(f)` → `Suggest(ViewExternalTemplates(f))`
  {severity: warn, message: "Document references external template(s). Inspect RELs?", cooldown: 30m, tags:\[office,template]}
* **\[F-0004]** `IsExcel(f) ∧ HasXlm4Macro(f)` → `Suggest(ViewXlmSheets(f))`
  {severity: high, message: "Excel 4.0 macro sheet present. Review it?", cooldown: 30m, tags:\[excel,xlm]}
* **\[F-0005]** `IsExcel(f) ∧ HasHiddenSheets(f)` → `Suggest(ViewHiddenSheets(f))`
  {severity: warn, message: "Hidden/VeryHidden sheets found. Show list?", cooldown: 30m, tags:\[excel,stealth]}
* **\[F-0006]** `IsPowerPoint(f) ∧ PptHasActionButtonMacro(f)` → `Suggest(ViewPptActions(f))`
  {severity: warn, message: "Action buttons invoke code. Inspect?", cooldown: 30m, tags:\[ppt,macro]}

### A2. PDF / RTF / OLE

* **\[F-0010]** `IsPdf(f) ∧ PdfHasJavaScript(f)` → `Suggest(ViewPdfJavaScript(f))`
  {severity: high, message: "Embedded JavaScript present. Inspect code?", cooldown: 30m, tags:\[pdf,script]}
* **\[F-0011]** `IsPdf(f) ∧ PdfHasOpenAction(f)` → `Suggest(ViewPdfObjects(f))`
  {severity: high, message: "Auto‑action triggers on open. Inspect object tree?", cooldown: 30m, tags:\[pdf,autorun]}
* **\[F-0012]** `IsRtf(f) ∧ ContainsKnownExploitArtifacts(f)` → `Suggest(ViewRtfControls(f))`
  {severity: high, message: "Exploitation artifacts in RTF. Review control words?", cooldown: 30m, tags:\[rtf,exploit]}
* **\[F-0013]** `AbusesEquationEditor(f)` → `Suggest(ViewOleObjects(f))`
  {severity: high, message: "Legacy Equation Editor usage. Inspect OLE objects?", cooldown: 30m, tags:\[office,ole]}

### A3. Script families (PS1/JS/VBS/HTA)

* **\[F-0020]** `IsScript(f) ∧ HasObfuscatedStrings(f)` → `Suggest(BeautifyScript(f))`
  {severity: high, message: "Obfuscated script. Beautify for review?", cooldown: 30m, tags:\[script,obfuscation]}
* **\[F-0021]** `IsPowerShellScript(f) ∧ ContainsDownloaderCode(f)` → `Suggest(ViewDynamicEval(f))`
  {severity: high, message: "Downloader patterns found. Inspect dynamic invocation?", cooldown: 30m, tags:\[ps1,downloader]}
* **\[F-0022]** `IsHTA(f) ∧ ContainsUrl(f)` → `Suggest(ViewScriptSource(f))`
  {severity: warn, message: "HTA with URLs. Open source view?", cooldown: 30m, tags:\[hta]}

### A4. PE/ELF/Mach‑O (static)

* **\[F-0030]** `IsPe(f) ∧ HasHighEntropy(f)` → `Suggest(IdentifyPacker(f))`
  {severity: warn, message: "High entropy indicates packing. Identify packer?", cooldown: 30m, tags:\[pe,packing]}
* **\[F-0031]** `IsPe(f) ∧ ContainsEmbeddedExecutable(f)` → `Suggest(ViewResources(f))`
  {severity: warn, message: "Embedded payloads detected. Inspect resources?", cooldown: 30m, tags:\[pe,resources]}
* **\[F-0032]** `IsPe(f) ∧ ¬IsSigned(f)` → `Suggest(ViewSignature(f))`
  {severity: info, message: "Binary is unsigned. Review signature panel for certainty?", cooldown: 30m, tags:\[pe,signing]}
* **\[F-0033]** `IsPe(f) ∧ IsSigned(f) ∧ ¬SignatureValid(f)` → `Suggest(ViewSignatureProblems(f))`
  {severity: high, message: "Invalid/revoked signature. Inspect chain & timestamp?", cooldown: 30m, tags:\[pe,signing]}

### A5. Archives / Installers / Shortcuts

* **\[F-0040]** `IsArchive(f) ∧ ArchiveIsPasswordProtected(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Password‑protected archive. Safe‑extract to sandbox?", cooldown: 30m, tags:\[archive,safety]}
* **\[F-0041]** `IsArchive(f) ∧ ArchiveContainsExecutable(f)` → `Suggest(ViewArchiveManifest(f))`
  {severity: warn, message: "Executable(s) inside archive. Review manifest?", cooldown: 30m, tags:\[archive]}
* **\[F-0042]** `IsInstaller(f) ∧ MsiRunsCustomAction(f)` → `Suggest(ViewMsiCustomActions(f))`
  {severity: warn, message: "MSI CustomAction(s) found. Inspect?", cooldown: 30m, tags:\[msi]}
* **\[F-0043]** `IsLnk(f) ∧ IsShortcutAbuseCandidate(f)` → `Suggest(ViewLnkTarget(f))`
  {severity: high, message: "LNK launches external content. Review target & args?", cooldown: 30m, tags:\[lnk]}

### A6. Reputation / Provenance

* **\[F-0050]** `MarkOfTheWeb(f)` → `Suggest(ViewMOTW(f))`
  {severity: info, message: "Internet‑origin marker present. Inspect source zone?", cooldown: 30m, tags:\[provenance]}
* **\[F-0051]** `HashInThreatIntel(f)` → `Suggest(ViewThreatIntelHits(f))`
  {severity: critical, message: "Known bad hash in intel. Review details immediately?", cooldown: 5m, tags:\[intel]}
* **\[F-0052]** `IsSigned(f) ∧ SignatureValid(f) ∧ SignedByKnownVendor(f)` → `Suggest(RecordPublisherTrust(f))`
  {severity: info, message: "Trusted publisher signature. Record as benign candidate?", cooldown: 1h, tags:\[trust]}

---

## B) USER‑ONLY TRIGGERS → SUGGESTIONS

> Coach the analyst based on **coverage gaps** and **workflow hygiene**.

### B1. Coverage reminders

* **\[U-0100]** `Opened(f) ∧ ¬ViewedHashes(f)` → `Suggest(ComputeHashes(f))`
  {severity: info, message: "Compute hashes for correlation & TI lookups?", cooldown: 30m, tags:\[workflow,hash]}
* **\[U-0101]** `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any)` → `Suggest(QueryThreatIntel(f))`
  {severity: info, message: "Check reputation across intel sources?", cooldown: 30m, tags:\[workflow,intel]}
* **\[U-0102]** `Opened(f) ∧ ¬ViewedStrings(f)` → `Suggest(ViewStrings(f))`
  {severity: info, message: "Review strings for URLs, IOCs and clues?", cooldown: 45m, tags:\[strings]}
* **\[U-0103]** `Opened(f) ∧ ¬StaticReviewed(f)` → `Suggest(OpenStaticChecklist(f))`
  {severity: info, message: "Finish static triage checklist?", cooldown: 45m, tags:\[checklist]}

### B2. Dynamic workflow

* **\[U-0110]** `LaunchedInSandbox(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: warn, message: "Sandbox run active. Review process tree?", cooldown: 15m, tags:\[dynamic]}
* **\[U-0111]** `LaunchedInSandbox(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: warn, message: "Network telemetry available. Check connections?", cooldown: 15m, tags:\[dynamic,network]}
* **\[U-0112]** `LaunchedInSandbox(f) ∧ ¬ViewedFileSystemActivity(f)` → `Suggest(ViewFileWrites(f))`
  {severity: info, message: "Review filesystem changes?", cooldown: 15m, tags:\[dynamic,fs]}
* **\[U-0113]** `LaunchedInSandbox(f) ∧ ¬ViewedRegistryActivity(f)` → `Suggest(ViewRegistryChanges(f))`
  {severity: info, message: "Review registry changes?", cooldown: 15m, tags:\[dynamic,registry]}

### B3. Safety & discipline

* **\[U-0120]** `Opened(f) ∧ IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Use protected view to avoid executing active content?", cooldown: 30m, tags:\[safety]}
* **\[U-0121]** `Opened(f) ∧ MarkOfTheWeb(f) ∧ ¬SwitchedToIsolatedNetwork(sbx)` → `Suggest(SwitchToIsolatedNetwork(sbx))`
  {severity: high, message: "Switch sandbox to no‑Internet profile?", cooldown: 30m, tags:\[sandbox]}
* **\[U-0122]** `Opened(f) ∧ ¬CreatedSnapshot(sbx, any)` → `Suggest(CreateSnapshot(sbx))`
  {severity: info, message: "Create VM snapshot before detonation?", cooldown: 1h, tags:\[safety,snapshot]}

### B4. Case hygiene

* **\[U-0130]** `IsSuspicious(f) ∧ ¬AddedToCase(f, any)` → `Suggest(AddToCase(f))`
  {severity: info, message: "Track this file in your case?", cooldown: 1h, tags:\[case]}
* **\[U-0131]** `IsMalicious(f) ∧ ¬GeneratedReport(f, any)` → `Suggest(GenerateReport(f))`
  {severity: high, message: "Generate a report with observed IOCs?", cooldown: 1h, tags:\[report]}
* **\[U-0132]** `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any)` → `Suggest(ExportIOCs(f))`
  {severity: info, message: "Export IOCs (CSV/STIX) for sharing?", cooldown: 1h, tags:\[ioc]}
* **\[U-0133]** `AddedToCase(f, caseId) ∧ ¬AssignedTo(self, f)` → `Suggest(AssignToSelf(f))`
  {severity: info, message: "Assign ownership to yourself?", cooldown: 1h, tags:\[case,ownership]}

---

## C) MIXED TRIGGERS (FILE + USER) → SUGGESTIONS

> “Do X because Y is present **and** you haven’t looked at Z.”

### C1. Office / Macros (deep)

* **\[M-0200]** `IsWord(f) ∧ HasMacros(f) ∧ ¬ViewedMacros(f)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros present. Open Macro Viewer?", cooldown: 30m, tags:\[office,macro]}
* **\[M-0201]** `HasMacroObfuscation(f) ∧ ¬DeobfuscatedVBA(f)` → `Suggest(DeobfuscateVBA(f))`
  {severity: high, message: "Obfuscated macros found. Deobfuscate now?", cooldown: 30m, tags:\[macro,obfuscation]}
* **\[M-0202]** `HasSuspiciousMacroFunctionCalls(f) ∧ ¬ViewedSuspiciousCalls(f)` → `Suggest(ViewSuspiciousCalls(f))`
  {severity: high, message: "Suspicious macro APIs detected. Review call list?", cooldown: 30m}
* **\[M-0203]** `ContainsExternalTemplateRef(f) ∧ ¬ViewedExternalTemplateRels(f)` → `Suggest(ViewExternalTemplates(f))`
  {severity: warn, message: "Remote template reference. Inspect RELs?", cooldown: 30m}
* **\[M-0204]** `HasMacroPersistence(f) ∧ ¬PersistenceReviewed(f)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "Macro attempts persistence. Review startup/task/service writes?", cooldown: 30m}

### C2. Strings / Blobs / Carving

* **\[M-0210]** `ContainsBase64Blobs(f) ∧ ¬DecodedBase64Blobs(f)` → `Suggest(DecodeBase64(f))`
  {severity: warn, message: "Base64 blobs detected. Decode for payloads?", cooldown: 30m}
* **\[M-0211]** `ContainsHexBlobs(f) ∧ ¬DecodedHexBlobs(f)` → `Suggest(DecodeHex(f))`
  {severity: info, message: "Hex blobs present. Decode now?", cooldown: 30m}
* **\[M-0212]** `ContainsUrl(f) ∧ ¬ExtractedUrls(f)` → `Suggest(ExtractUrls(f))`
  {severity: info, message: "Extract URLs for pivoting & blocking?", cooldown: 30m}
* **\[M-0213]** `ContainsEmbeddedArchive(f) ∧ ¬CarvedEmbeddedFiles(f)` → `Suggest(CarveEmbedded(f))`
  {severity: warn, message: "Embedded archive(s) found. Carve safely?", cooldown: 30m}
* **\[M-0214]** `ContainsEmbeddedExecutable(f) ∧ ¬CarvedEmbeddedFiles(f)` → `Suggest(CarveEmbedded(f))`
  {severity: high, message: "Embedded executable detected. Extract for triage?", cooldown: 30m}

### C3. PE / Native (static+user)

* **\[M-0220]** `IsPe(f) ∧ ¬ViewedImports(f)` → `Suggest(ViewImports(f))`
  {severity: info, message: "Review imported APIs for intent?", cooldown: 45m}
* **\[M-0221]** `IsPe(f) ∧ HasHighEntropy(f) ∧ ¬RanPackerId(f)` → `Suggest(IdentifyPacker(f))`
  {severity: warn, message: "Likely packed. Identify packer?", cooldown: 45m}
* **\[M-0222]** `IsPe(f) ∧ ¬ViewedResources(f) ∧ ContainsEmbeddedScript(f)` → `Suggest(ViewResources(f))`
  {severity: warn, message: "Script content embedded. Inspect resources?", cooldown: 45m}
* **\[M-0223]** `IsPe(f) ∧ ¬ViewedOverlay(f) ∧ HasOverlayData(f)` → `Suggest(ViewOverlay(f))`
  {severity: info, message: "Overlay data present. Inspect trailing bytes?", cooldown: 45m}

### C4. Dynamic / Behavior

* **\[M-0230]** `TriesToAccessTheInternet(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "Outbound connections observed. Review endpoints?", cooldown: 20m}
* **\[M-0231]** `BeaconingPattern(f) ∧ ¬ResolvedDomains(f)` → `Suggest(ViewDnsQueries(f))`
  {severity: high, message: "Beaconing detected. Review DNS queries/domains?", cooldown: 20m}
* **\[M-0232]** `UsesHTTPSRequests(f) ∧ UsesSelfSignedTls(f) ∧ ¬ViewedTlsCertificates(f)` → `Suggest(ViewTlsCertificates(f))`
  {severity: high, message: "Self‑signed/invalid TLS. Inspect certificate chain?", cooldown: 20m}
* **\[M-0233]** `WritesToTempExecutable(f) ∧ ¬ViewedFileSystemActivity(f)` → `Suggest(ViewFileWrites(f))`
  {severity: high, message: "New executable(s) in temp. Review drops?", cooldown: 20m}
* **\[M-0234]** `DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "Drop‑and‑run sequence observed. Open process tree?", cooldown: 20m}
* **\[M-0235]** `CreatesRunKey(f) ∧ ¬ViewedRegistryActivity(f)` → `Suggest(ViewRegistryChanges(f))`
  {severity: high, message: "Startup persistence detected. Inspect registry changes?", cooldown: 20m}

### C5. Persistence / Privilege

* **\[M-0240]** `PersistenceIndicatorsPresent(f) ∧ ¬PersistenceReviewed(f)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "Persistence artifacts found. Review them now?", cooldown: 30m}
* **\[M-0241]** `RequestsUacElevation(f) ∧ ¬ViewedUacEvents(f)` → `Suggest(ViewUac(f))`
  {severity: warn, message: "UAC prompt/elevation attempt. Inspect event details?", cooldown: 30m}
* **\[M-0242]** `AcquiresSeDebugPrivilege(f) ∧ ¬ViewedTokenPrivileges(f)` → `Suggest(ViewTokenPrivileges(f))`
  {severity: high, message: "Debug privilege acquired. Review token changes?", cooldown: 30m}

### C6. Ransomware / Destruction

* **\[M-0250]** `MassFileModification(f) ∧ ¬ViewedEncryptionMonitor(f)` → `Suggest(MonitorEncryption(f))`
  {severity: critical, message: "Rapid file modifications. Start encryption monitor?", cooldown: 10m}
* **\[M-0251]** `DeletesShadowCopies(f) ∧ ¬ViewedShadowCopyEvents(f)` → `Suggest(ViewShadowCopyEvents(f))`
  {severity: high, message: "VSS deletion observed. Inspect events?", cooldown: 20m}
* **\[M-0252]** `DropsRansomNote(f) ∧ ¬ViewedRansomNotes(f)` → `Suggest(ViewRansomNotes(f))`
  {severity: high, message: "Ransom note artifacts dropped. Open list?", cooldown: 20m}

### C7. Exfiltration / Espionage

* **\[M-0260]** `ReadsManyDocs(f) ∧ ¬ViewedExfilTimeline(f)` → `Suggest(ViewExfil(f))`
  {severity: high, message: "Mass document reads. Check exfil timeline?", cooldown: 20m}
* **\[M-0261]** `CompressesBeforeUpload(f) ∧ ¬ViewedArchiveManifest(f)` → `Suggest(ViewArchiveManifest(f))`
  {severity: warn, message: "Local staging via archive. Inspect staged files?", cooldown: 20m}
* **\[M-0262]** `UploadsLargeVolume(f) ∧ ¬CapturedPcap(f)` → `Suggest(StartCapturePcap(f))`
  {severity: high, message: "Large outbound traffic. Capture PCAP now?", cooldown: 15m}

### C8. Anti‑analysis / Evasion

* **\[M-0270]** `ChecksSandboxArtifacts(f) ∧ ¬ViewedAntiVMChecks(f)` → `Suggest(ViewAntiVM(f))`
  {severity: warn, message: "Anti‑VM checks observed. Review heuristics?", cooldown: 30m}
* **\[M-0271]** `DelaysExecutionLong(f) ∧ ¬EnabledTimeWarp(f)` → `Suggest(EnableTimeWarp(f))`
  {severity: info, message: "Long sleeps observed. Enable time warp?", cooldown: 30m}
* **\[M-0272]** `UsesParentPidSpoofing(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "PPID spoofing suspected. Inspect lineage?", cooldown: 20m}

### C9. Archives / Installers / LNK (mixed)

* **\[M-0280]** `IsArchive(f) ∧ ArchiveIsPasswordProtected(f) ∧ ¬ExtractedArchiveSafely(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Password‑protected archive. Extract to sandbox?", cooldown: 30m}
* **\[M-0281]** `IsInstaller(f) ∧ MsiRunsCustomAction(f) ∧ ¬ViewedMsiCustomActions(f)` → `Suggest(ViewMsiCustomActions(f))`
  {severity: warn, message: "MSI CustomAction(s) present. Inspect?", cooldown: 30m}
* **\[M-0282]** `IsLnk(f) ∧ IsShortcutAbuseCandidate(f) ∧ ¬ViewedLnkTarget(f)` → `Suggest(ViewLnkTarget(f))`
  {severity: high, message: "Suspicious shortcut target. Review args & path?", cooldown: 30m}

### C10. Provenance / Reputation / Reporting

* **\[M-0290]** `ComputedHashes(f) ∧ ¬QueriedThreatIntel(f, any) ∧ (ContainsUrl(f) ∨ TriesToAccessTheInternet(f))` → `Suggest(QueryThreatIntel(f))`
  {severity: info, message: "Reputation check likely useful here. Query TI?", cooldown: 30m}
* **\[M-0291]** `InternetOriginCorroborated(f) ∧ IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Internet‑delivered active content. Use safe view?", cooldown: 30m}
* **\[M-0292]** `IsSuspicious(f) ∧ ¬ExtractedIOCs(f)` → `Suggest(ExtractIOCs(f))`
  {severity: high, message: "Extract IOCs to pivot and contain?", cooldown: 45m}
* **\[M-0293]** `ExtractedIOCs(f) ∧ ¬ExportedIOCs(f, any)` → `Suggest(ExportIOCs(f))`
  {severity: info, message: "Export IOCs (CSV/STIX) for sharing?", cooldown: 1h}
* **\[M-0294]** `IsMalicious(f) ∧ ¬GeneratedReport(f, any)` → `Suggest(GenerateReport(f))`
  {severity: high, message: "Generate a concise report with findings?", cooldown: 1h}

---

## D) TIME‑WINDOWED PLAYBOOKS (sequenced coaching)

* **\[P-0300]** `IsWord(f) ∧ HasMacros(f) ∧ UserEnabledMacros(u,f) ∧ ¬ViewedMacros(f) ∧ Within(5m)` → `Suggest(ViewMacros(f))`
  {severity: high, message: "Macros executed recently. Inspect source now.", cooldown: 15m}
* **\[P-0301]** `WritesToTempExecutable(f) ∧ DropsAndExecutes(f) ∧ ¬ViewedProcessTree(f) ∧ Within(3m)` → `Suggest(ViewProcessTree(f))`
  {severity: high, message: "Drop‑and‑run chain just occurred. Open process graph.", cooldown: 15m}
* **\[P-0302]** `DownloadsFromInternet(f) ∧ ¬ViewedNetworkBehavior(f) ∧ Within(10m)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "Recent download observed. Review network flows.", cooldown: 20m}
* **\[P-0303]** `CreatesRunKey(f) ∧ ¬PersistenceReviewed(f) ∧ Within(10m)` → `Suggest(ViewPersistence(f))`
  {severity: high, message: "New persistence. Review startup artifacts.", cooldown: 20m}
* **\[P-0304]** `BeaconingPattern(f) ∧ ¬CapturedPcap(f) ∧ Within(15m)` → `Suggest(StartCapturePcap(f))`
  {severity: high, message: "Beaconing ongoing. Capture PCAP for C2 analysis.", cooldown: 15m}

---

## E) SAFETY & ISOLATION GUARDRAILS

> Only propose potentially risky actions when the environment is safe.

* **\[S-0400]** `IsActiveContentCapable(f) ∧ ¬OpenedSafely(f)` → `Suggest(OpenInSafeView(f))`
  {severity: high, message: "Use protected view to avoid code execution.", cooldown: 30m}
* **\[S-0401]** `TriesToAccessTheInternet(f) ∧ ¬SwitchedToIsolatedNetwork(sbx)` → `Suggest(SwitchToIsolatedNetwork(sbx))`
  {severity: high, message: "Switch to isolated/no‑Internet sandbox.", cooldown: 30m}
* **\[S-0402]** `EncryptsManyFiles(f) ∧ ¬SetReadonlyDirs(sbx, any)` → `Suggest(ProtectUserDirs(sbx))`
  {severity: critical, message: "Protect user directories (read‑only policy).", cooldown: 10m}
* **\[S-0403]** `Opened(f) ∧ ¬CreatedSnapshot(sbx, any)` → `Suggest(CreateSnapshot(sbx))`
  {severity: info, message: "Create VM snapshot before detonation.", cooldown: 1h}

---

## F) PRIORITIZATION, DEDUP & META‑SUGGESTIONS

> Manage suggestion noise and coach next best action.

* **\[X-0500]** `Dismissed(Suggest(X))` → `Suppress(Suggest(X), 1h)`
  {severity: info, message: "Muted for 1 hour.", cooldown: 0}
* **\[X-0501]** `Snoozed(Suggest(X), Δt)` → `Suppress(Suggest(X), Δt)`
  {severity: info, message: "Snoozed.", cooldown: 0}
* **\[X-0502]** `IsMalicious(f) ∧ MultipleSuggestionsPending(f) → PrioritizeSuggestions(f, order=["ViewProcessTree","ViewNetwork","ViewPersistence","ExtractIOCs","GenerateReport"])`
  {severity: high, message: "Prioritizing critical next steps.", cooldown: 10m}
* **\[X-0503]** `LikelyBenign(f) ∧ Suggest(LaunchSandbox(f))` → `DowngradeSeverity(Suggest(LaunchSandbox(f)))`
  {severity: info, message: "Sandbox detonation optional for benign‑leaning sample.", cooldown: 1h}

---

## G) CAMPAIGN / CORRELATION COACHING

* **\[C-0600]** `ClusteredC2Campaign(f, any) ∧ ¬ViewedBehaviorDiff(f, any)` → `Suggest(ViewCampaignDiffs(f))`
  {severity: info, message: "Compare behavior across cluster samples.", cooldown: 1h}
* **\[C-0601]** `SimilarToKnownBad(f) ∧ ¬ComparedAgainstBaseline(f)` → `Suggest(DiffWithKnownBad(f))`
  {severity: info, message: "Diff against prior known‑bad to speed triage.", cooldown: 1h}
* **\[C-0602]** `HashInThreatIntel(f) ∧ ¬AddedToCase(f, any)` → `Suggest(AddToCase(f))`
  {severity: high, message: "Track intel‑matched sample in your case.", cooldown: 1h}

---

## H) EMAIL / PHISHING CONTEXT

* **\[E-0700]** `SourceIsEmailAttachment(f) ∧ HasSuspiciousAttachment(f) ∧ ¬ViewedOrigin(f)` → `Suggest(ViewOrigin(f))`
  {severity: warn, message: "Check message headers and sender context.", cooldown: 45m}
* **\[E-0701]** `SourceIsEmailAttachment(f) ∧ MarkOfTheWeb(f) ∧ ¬ViewedMOTW(f)` → `Suggest(ViewMOTW(f))`
  {severity: info, message: "Attachment marked Internet‑origin. Review zone data.", cooldown: 45m}
* **\[E-0702]** `IsPhishingEmail(f) ∧ LinksToCredentialHarvestingSite(f) ∧ ¬ExtractedIOCs(f)` → `Suggest(ExtractIOCs(f))`
  {severity: high, message: "Extract URLs/domains for blocking.", cooldown: 45m}

---

## I) ARCHIVE / INSTALLER PLAYBOOKS

* **\[A-0800]** `IsArchive(f) ∧ ArchiveDoubleExtensionMembers(f) ∧ ¬ViewedDoubleExtensions(f)` → `Suggest(ViewDoubleExtensions(f))`
  {severity: warn, message: "Suspicious member names (.pdf.exe). Review.", cooldown: 45m}
* **\[A-0801]** `IsArchive(f) ∧ ArchiveContainsScript(f) ∧ ¬ExtractedArchiveSafely(f)` → `Suggest(SafeExtract(f))`
  {severity: warn, message: "Scripts inside. Safe‑extract to sandbox.", cooldown: 45m}
* **\[A-0802]** `IsInstaller(f) ∧ (BinarySpawnsScripting(f) ∨ DownloadsFromInternet(f)) ∧ ¬LaunchedInSandbox(f)` → `Suggest(LaunchSandbox(f))`
  {severity: high, message: "Installer exhibits risky behavior. Detonate safely.", cooldown: 30m}

---

## J) LATERAL MOVEMENT / CREDENTIAL ACCESS

* **\[L-0900]** `UsesWmiForExec(f) ∧ ¬ViewedWmiSubscriptions(f)` → `Suggest(ViewWmiSubscriptions(f))`
  {severity: high, message: "WMI activity. Inspect subscriptions/consumers.", cooldown: 30m}
* **\[L-0901]** `UsesSmb(f) ∧ ¬ViewedNetworkBehavior(f)` → `Suggest(ViewNetwork(f))`
  {severity: high, message: "SMB connections observed. Review peers.", cooldown: 30m}
* **\[L-0902]** `ReadsLsassMemory(f) ∧ ¬ViewedTokenPrivileges(f)` → `Suggest(ViewTokenPrivileges(f))`
  {severity: critical, message: "Credential theft indicator. Review token scope.", cooldown: 15m}
* **\[L-0903]** `UsesPsExecLike(f) ∧ ¬ViewedProcessTree(f)` → `Suggest(ViewProcessTree(f))`
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