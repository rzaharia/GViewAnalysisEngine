# GView Analysis engine
## File facts

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

## 1) Type & Container Identification (Static)

* `IsWord(f)` — MS Word document family. **Set** if magic/MIME/extension indicates Word (.doc/.docx/.docm/.rtf).
* `IsDoc(f)` — Legacy Word Binary (.doc). **Set** if OLE Compound File w/ `WordDocument` stream.
* `IsDocx(f)` — Office Open XML Word (.docx). **Set** if ZIP container with `[Content_Types].xml` + Word parts, no VBA.
* `IsDocm(f)` — Macro-enabled Word (.docm). **Set** if OOXML + `vbaProject.bin`.
* `IsRtf(f)` — Rich Text Format. **Set** if RTF header `{\rtf`.
* `IsExcel(f)` / `IsXls(f)` / `IsXlsx(f)` / `IsXlsm(f)` — Excel family. **Set** via OLE/OOXML cues.
* `HasExcel4Macros(f)` — XLM macros present. **Set** if `xlm` macro sheets exist/hidden.
* `IsPowerPoint(f)` / `IsPpt(f)` / `IsPptx(f)` / `IsPptm(f)` — PPT family. **Set** via OLE/OOXML cues.
* `IsPdf(f)` — PDF file. **Set** if `%PDF-` header / xref, trailer.
* `IsHtml(f)` — HTML. **Set** if `<!DOCTYPE html>` / `<html>` dominance.
* `IsChm(f)` — Compiled HTML Help. **Set** if ITSF format (`ITSF` magic).
* `IsLnk(f)` — Windows shortcut. **Set** by Shell Link format signature.
* `IsScript(f)` — Generic script. **Set** if `.vbs`, `.js`, `.ps1`, `.bat`, `.cmd`, `.hta`, etc.
* `IsVBScript(f)` / `IsJScript(f)` / `IsPowerShellScript(f)` / `IsBatchScript(f)` / `IsHTA(f)`. **Set** via extension or shebang/content cues.
* `IsArchive(f)` — Archive container. **Set** if ZIP/RAR/7z/TAR signatures.
* `IsInstaller(f)` — Installer package. **Set** if MSI/WIX/InstallShield cues.
* `IsPe(f)` — Windows PE (EXE/DLL/SYS). **Set** if `MZ` + PE header.
* `IsElf(f)` — Linux ELF. **Set** if `0x7f ELF`.
* `IsMachO(f)` — macOS Mach-O/Universal Binary. **Set** via Mach-O headers / FAT.
* `IsDriver(f)` — Kernel driver. **Set** if PE/ELF/Mach-O w/ driver characteristics.
* `IsJar(f)` — Java JAR. **Set** if ZIP + `META-INF/MANIFEST.MF`.
* `IsIso(f)` / `IsVhdx(f)` / `IsDmg(f)` — Disk images. **Set** via format signature.
* `IsEmailMessage(f)` — EML/MSG. **Set** by MIME headers or MAPI MSG structure.
* `IsShortcutAbuseCandidate(f)` — LNK pointing to script/exe with arguments. **Set** if LNK `TargetPath` or `Arguments` suspicious.

---

## 2) Packaging, Encryption, Obfuscation (Static)

* `IsEncrypted(f)` — Encrypted container/content. **Set** if encrypted stream flags (OOXML), or PDF `Encrypt` dict, or high-entropy across critical streams.
* `IsPasswordProtected(f)` — Password required to open. **Set** if Office protection flags or archive indicates password.
* `HasHighEntropy(f)` — Likely packed/obfuscated. **Set** if average entropy above threshold (e.g., >7.2) on code/streams.
* `IsPacked(f)` — Recognized packer. **Set** by PE section signatures, UPX headers, or heuristics (overlay, imports).
* `HasOverlayData(f)` — Extra data appended. **Set** if bytes beyond last defined section/central directory.
* `HasObfuscatedStrings(f)` — String hiding. **Set** if many base64/hex chunks, string concat patterns, `Chr`/`Xor` usage.
* `ContainsEmbeddedArchive(f)` — Archive inside. **Set** if ZIP/RAR headers found in streams/resources.
* `ContainsEmbeddedExecutable(f)` — PE/ELF inside. **Set** if nested binary signatures found.
* `ContainsEmbeddedScript(f)` — Script text in non-script file. **Set** if PowerShell/JS/VBS indicators in resources/streams.

---

## 3) Authenticode, Notarization, Reputation (Static)

* `IsSigned(f)` — Has digital signature. **Set** if Authenticode/PKCS#7 present (PE), OOXML signature, PDF signature.
* `SignatureValid(f)` — Chain + hash valid. **Set** after signature verification succeeds.
* `SignatureTimestamped(f)` — Countersignature present. **Set** if RFC3161 timestamp or Authenticode TS.
* `SignatureRevoked(f)` — Cert revoked. **Set** via CRL/OCSP results.
* `SignedByKnownVendor(f)` — Whitelisted publisher. **Set** if subject matches trusted list.
* `IsAppleNotarized(f)` — macOS Notarization. **Set** if ticket exists/valid (for Mach-O).
* `HashInThreatIntel(f)` — Known-bad hash. **Set** if SHA-256/SHA-1 present in local intel DB.
* `HashInKnownGood(f)` — Known-good whitelist. **Set** if matches clean baseline.
* `MarkOfTheWeb(f)` — MOTW present. **Set** if Windows Zone.Identifier ADS or alternate metadata zone.

---

## 4) Content Indicators (Static)

* `ContainsUrl(f)` — One or more URLs. **Set** if regex finds valid URLs.
* `ContainsIpLiteral(f)` — Hard-coded IPs. **Set** by IPv4/IPv6 regex matches.
* `ContainsEmailAddress(f)` — Email presence. **Set** by RFC 5322 pattern matches.
* `ContainsSuspiciousKeywords(f)` — e.g., `powershell`, `cmd.exe`, `wscript`, `rundll32`, `regsvr32`. **Set** if found in strings.
* `ContainsBase64Blobs(f)` / `ContainsHexBlobs(f)` — Potential payloads. **Set** if long Base64/hex sequences detected.
* `ContainsDownloaderCode(f)` — Code that fetches content. **Set** if `URLDownloadToFile`, `WinHttpRequest`, `WebClient`, `BitsTransfer` present.
* `ContainsPersistenceArtifacts(f)` — Startup/task/service strings. **Set** if `Run\`, `schtasks`, `LaunchAgents`, etc., found.
* `ContainsVbaProject(f)` — VBA project embedded. **Set** if OLE `VBA` streams exist.
* `ContainsExternalTemplateRef(f)` — Remote/injected template. **Set** if `word/_rels/document.xml.rels` points to external template.

---

## 5) User-Driven Context (User Path)
Facts when deadling with logs of actions done by the user.

* `UserOpenedWithGView(u,f)` — GView loaded the file. **Set** on open event.
* `UserDoubleClicked(u,f)` — OS shell open. **Set** via shell event telemetry (if available).
* `UserEnabledMacros(u,f)` — “Enable Content” clicked. **Set** if Word telemetry, audit log, or macro execution observed.
* `UserIgnoredSmartScreen(u,f)` — Bypassed warning. **Set** if SmartScreen events show override.
* `UserRanAsAdmin(u,f)` — Elevated execution. **Set** if token elevation at launch.
* `UserDownloadedFrom(u,f,src)` — Browser/email/IM source. **Set** by browser history, email message link, or MOTW referrer.
* `UserMountedImage(u,v)` — Mounted ISO/VHD/DMG. **Set** if system mount event observed.
* `SourceIsEmailAttachment(f)` — Origin from mail. **Set** by EML/MSG relationship, or mail client cache.
* `SourceIsRemovableMedia(f)` / `SourceIsNetworkShare(f)` / `SourceIsCloudSyncFolder(f)`. **Set** by file path prefix or volume attributes.

---

## 6) File System Behavior (Runtime)

* `WritesToTempExecutable(f)` — Drops EXE/DLL to temp. **Set** if write event creates PE in `%TEMP%`.
* `WritesOfficeStartupPath(f)` — Writes to `Startup`/`XLSTART`. **Set** by path match.
* `WritesToSystemDir(f)` — Writes to `System32`, `/bin`, etc. **Set** by path and ACL.
* `ModifiesHostsFile(f)` — Edits hosts. **Set** if write to hosts path detected.
* `CreatesHiddenFile(f)` / `SetsAlternateDataStream(f)` — **Set** on FS metadata change.
* `MassFileModification(f)` — Many writes across user docs. **Set** if write count/coverage surpass threshold.
* `DeletesShadowCopies(f)` — Invokes `vssadmin`/WMI to delete. **Set** on process command-line or API usage.
* `EncryptsManyFiles(f)` — Ransomware pattern. **Set** if many files rewritten with high-entropy contents and extension changes.
* `DropsRansomNote(f)` — Ransom note artifact. **Set** if new files with common note names appear.

---

## 7) Process & Memory Behavior (Runtime)

* `SpawnsCmd(f)` / `SpawnsPowerShell(f)` / `SpawnsWscript(f)` / `SpawnsCscript(f)` / `SpawnsMshta(f)` / `SpawnsRundll32(f)` / `SpawnsRegsvr32(f)` — **Set** if child process executable matches.
* `LoadsLibraryFromTemp(f)` — DLL load from temp. **Set** if module load path in temp.
* `CreatesRemoteThread(f)` / `WritesProcessMemory(f)` / `AllocatesRWXMemory(f)` — Injection indicators. **Set** via API tracing or ETW/audit.
* `UnhooksNtdll(f)` — EDR evasion attempt. **Set** if code patches known prologues.
* `DisablesSecurityTools(f)` — Kills/disables AV/EDR. **Set** if process/registry/service actions match list.
* `SetsProcessMitigationPolicy(f,weak)` — Weakens protections. **Set** if calls made to relax mitigations.
* `UsesDirectSyscalls(f)` — Bypass hooks. **Set** if unusual syscall stubs detected at runtime.
* `DropsAndExecutes(f)` — Write → execute chain. **Set** if file is created then launched by same parent.

---

## 8) Network & External Communications (Runtime)

* `TriesToAccessTheInternet(f)` — Any outbound connection. **Set** if `Conn(c)` with public IP.
* `UsesHTTPRequests(f)` / `UsesHTTPSRequests(f)` — **Set** if protocol parsing identifies HTTP(S).
* `UsesDnsOnlyBeaconing(f)` — DNS tunneling/beaconing. **Set** if periodic TXT/CNAME/NULL queries.
* `DnsQueriesDGA(f)` — Algorithmic domains. **Set** by DGA score of queried domains.
* `ConnectsToTor(f)` — Tor nodes. **Set** if IP/port matches Tor directory relays.
* `UsesSelfSignedTls(f)` — Self-signed/invalid certs. **Set** if TLS handshake reveals untrusted chain.
* `BeaconingPattern(f)` — Periodic uniform beacons. **Set** if inter-arrival times stable over window.
* `DownloadsFromInternet(f)` — Receives file payload. **Set** if HTTP GET/POST or other protocol transfers result in a saved file.
* `UploadsLargeVolume(f)` — Possible exfil. **Set** if outbound data volume over threshold.
* `UsesSmb(f)` / `UsesWmiRemote(f)` / `UsesWinRm(f)` — Lateral channels. **Set** based on connection endpoints/commands.
* `UsesFtpOrSftp(f)` / `UsesSsh(f)` — **Set** by protocol detection.
* `UsesCloudStorageApi(f)` — Dropbox/OneDrive/GDrive/Box patterns. **Set** via API endpoints/UA strings.
* `UsesBitsTransfer(f)` — Background Intelligent Transfer. **Set** if BITS jobs created.

---

## 9) Persistence (Runtime / System Changes)

* `CreatesRunKey(f)` — `HKCU/HKLM\...\Run*`. **Set** on registry write.
* `CreatesStartupShortcut(f)` — Shortcut in Startup folder. **Set** on file create.
* `CreatesScheduledTask(f)` — New scheduled task. **Set** if `schtasks`/TaskScheduler API called.
* `CreatesService(f)` — Installs Windows service. **Set** via Service Control Manager events.
* `ModifiesWinlogonShell(f)` / `ModifiesUserinit(f)` — **Set** on registry writes to Winlogon keys.
* `CreatesWmiEventSubscription(f)` — WMI persistence. **Set** if `__EventFilter`/`CommandLineEventConsumer` created.
* `CreatesBrowserExtensionPersistence(f)` — Adds/forces extension. **Set** via browser dirs/registry.
* `CreatesLaunchAgent(f)` / `CreatesLaunchDaemon(f)` — macOS persistence. **Set** if plist appears in LaunchAgents/Daemons.
* `CreatesCronJob(f)` / `CreatesSystemdService(f)` — Linux persistence. **Set** if crontab/systemd units appear.
* `AbusesOfficeStartupFolders(f)` — Drops templates/add-ins. **Set** if files in `~\AppData\Microsoft\Word\Startup` etc.

---

## 10) Privilege & Security Boundary (Runtime)

* `RequestsUacElevation(f)` — UAC prompt triggered. **Set** if elevation attempt noted.
* `BypassesUac(f)` — Silent admin rights. **Set** if known UAC-bypass patterns observed (class IDs, fodhelper etc.) **(track at heuristic level only)**.
* `AcquiresSeDebugPrivilege(f)` — Debug privilege. **Set** via `AdjustTokenPrivileges`.
* `ReadsLsassMemory(f)` — Credential theft attempt. **Set** if handle to `lsass.exe` with read perms.
* `DropsKernelDriver(f)` / `LoadsKernelDriver(f)` — Kernel-level activity. **Set** if service type = kernel driver or module load at ring 0.
* `ModifiesSecuritySettings(f)` — Disables Defender/Firewall. **Set** on registry/PowerShell cmdlets.

---

## 11) Discovery, Lateral Movement & Tooling (Runtime)

* `EnumeratesAd(f)` — AD queries. **Set** if LDAP/PowerShell AD modules used.
* `ScansNetwork(f)` — Port scanning/ARP sweep. **Set** if many distinct hosts/ports probed.
* `UsesPsExecLike(f)` — PsExec/Smbexec patterns. **Set** if `PSEXESVC`/`svcctl` RPC used.
* `UsesRemoteServiceCreation(f)` — SCM over RPC. **Set** if remote service install observed.
* `UsesWmiForExec(f)` — WMI `Win32_Process` create. **Set** via event logs/WMI provider.
* `ModifiesRdpSettings(f)` — Enables RDP. **Set** via registry edit or `netsh`/`powershell` commands.

---

## 12) Exploitation Indicators (Static + Runtime; heuristic-only)

*(Keep high-level so we don’t teach exploitation; focus on artifacts.)*

* `ContainsDdeField(f)` — Office DDE used. **Set** if DDE fields in document RELs/fields.
* `ContainsOleObjectAutoExec(f)` — OLE Packager auto-run. **Set** if auto-exec actions embedded.
* `ContainsKnownExploitArtifacts(f)` — CVE-linked markers. **Set** if YARA/intel hits match known Office/RTF exploit traits.
* `AbusesEquationEditor(f)` — Deprecated EQNEDT32 artifacts. **Set** by OLE object class IDs.
* `UsesShellcodeStubs(f)` — Generic shellcode patterns. **Set** by YARA/heuristics in streams/resources.
* `HeapSprayBehavior(f)` — Javascript/PDF sprays. **Set** if many NOP-like patterns + predictable allocations observed.

---

## 13) Anti-Analysis & Evasion (Runtime + Static)

* `ChecksSandboxArtifacts(f)` — Looks for sandbox VM files/paths. **Set** via string match & file queries.
* `DetectsDebugger(f)` — `IsDebuggerPresent`/timing checks. **Set** via API calls.
* `DelaysExecutionLong(f)` — Sleep > threshold. **Set** from timing or API call duration.
* `UsesParentPidSpoofing(f)` — Hollow/spoofed parent. **Set** if PPID inconsistent with UI chain.
* `DeletesItself(f)` — Self-delete. **Set** if file gone after execution.
* `EncryptsConfiguration(f)` — Config blob encrypted. **Set** if decrypted at runtime or high-entropy config detected.

---

## 14) Data Collection & Exfiltration (Runtime)

* `ReadsManyDocs(f)` — Enumerates & reads many office docs. **Set** if read count across user dirs high.
* `ScreenshotsTaken(f)` — Screenshot API usage. **Set** via GDI/Graphics capture calls.
* `KeyloggingBehavior(f)` — Keyboard hooks/raw input. **Set** via `SetWindowsHookEx` etc.
* `AccessesBrowserCredentialStores(f)` — Access to Chrome/Edge/Firefox DBs. **Set** if files opened or DPAPI calls with those targets.
* `CompressesBeforeUpload(f)` — ZIP/7z creation prior to send. **Set** if archive created then network upload.
* `UsesSteganography(f)` — Suspected stego. **Set** if image payload size anomalies / LSB patterns.

---

## 15) Ransomware-Specific (Runtime)

* `StopsServicesRelatedToBackups(f)` — Kills VSS/backup agents. **Set** by service control actions.
* `DeletesBackupCatalogs(f)` — **Set** if known backup files removed.
* `AppendsRansomExtension(f)` — New extension across many files. **Set** if pattern emerges.
* `PublishesTorContactInfo(f)` — Ransom note with onion addresses. **Set** by content scan.

---

## 16) Platform-Specific (macOS/Linux)

* `ModifiesSudoers(f)` — Linux sudoers edited. **Set** if `/etc/sudoers` or drop-in changed.
* `CreatesSetuidBinary(f)` — Privilege escalation vector. **Set** if setuid bit set on new binary.
* `CreatesLaunchAgent(f)` / `CreatesLaunchDaemon(f)` — macOS persistence. **Set** if new plist with `ProgramArguments` created.
* `LoadsKernelExtension(f)` — macOS kext load attempt. **Set** via system logs.
* `CreatesSystemdUserService(f)` — Linux persistence. **Set** if unit file added/started.

---

## 17) Email-Specific (If file is EML/MSG)

* `IsPhishingEmail(f)` — Phishing indicators. **Set** if SPF/DKIM/DMARC fail + suspicious wording/URLs.
* `HasMismatchedDisplayNameAndAddress(f)` — **Set** if `From:` name vs address mismatch.
* `HasSuspiciousAttachment(f)` — Attachment of risky type. **Set** if `.docm`, `.js`, `.vbs`, `.lnk`, `.iso`, `.img`, `.chm`.
* `LinksToCredentialHarvestingSite(f)` — **Set** via URL analysis (login pages, known kits).
* `AttachmentHasMOTW(f)` — Attachment downloaded from Internet. **Set** if MOTW present.

---

## 18) Word/VBA-Specific Macro Predicates (Static + Runtime)

* `HasMacros(f)` — Any VBA present. **Set** if `vbaProject.bin`/VBA streams exist.
* `HasAutoExecMacro(f)` — Auto-run macros. **Set** if `AutoOpen`, `Document_Open`, `AutoClose`, `Document_New` present.
* `HasSuspiciousMacroFunctionCalls(f)` — Dangerous API/COM calls. **Set** if `Shell`, `CreateObject`, `GetObject`, `URLDownloadToFile`, `WinHttpRequest`, `XMLHTTP`, `WScript.Shell`, `ADODB.Stream`, `PowerShell` found in VBA AST/strings.
* `HasMacroNetworkAccess(f)` — Network operations. **Set** if WinHTTP/XMLHTTP/WebClient usage.
* `HasMacroFileWrite(f)` — Writes to disk. **Set** if `Open ... For Output/Binary`, `ADODB.Stream.SaveToFile` etc.
* `HasMacroPersistence(f)` — Startup/task registry writes. **Set** if `WScript.Shell.RegWrite`, `schtasks`, `Copy` into Office startup paths.
* `HasMacroProcessSpawn(f)` — Spawns child process. **Set** if `Shell`, `WMI Win32_Process.Create`, `rundll32` calls.
* `HasMacroPowerShellInvocation(f)` — **Set** if command strings include `powershell.exe` or `-EncodedCommand`.
* `HasMacroDDE(f)` — Dynamic Data Exchange. **Set** if fields constructing DDE payloads.
* `HasMacroObfuscation(f)` — String/flow obfuscation. **Set** if heavy `Chr/AscW/Replace/Mid/StrReverse` with concatenation & non-literal arithmetic.
* `HasMacroBase64Decode(f)` — **Set** if base64 decode routines present.
* `HasMacroHexDecode(f)` — **Set** if hex-decoding loops/`&H` parsing present.
* `HasMacroEnvironmentChecks(f)` — Anti-analysis. **Set** if checks for username, computername, domain, processes (e.g., `vbox`, `wireshark`).
* `HasMacroExternalTemplate(f)` — Remote template injection. **Set** if `document.xml.rels` references remote DOTM/DOTX.
* `HasMacroDropsLnk(f)` — LNK creation. **Set** if `WScript.Shell.CreateShortcut`.
* `HasMacroOlePackage(f)` — OLE Packager object. **Set** if `Package` OLE objects embedded.
* `HasHiddenVbaModules(f)` — Hidden/protected modules. **Set** if `VB_Description`/`VB_Hidden` flags or project locked.
* `HasMacroRundll32Call(f)` / `HasMacroRegsvr32Call(f)` / `HasMacroMshtaCall(f)` — **Set** if command strings match those utilities.
* `HasMacroDownloadAndExecute(f)` — Network + spawn chain. **Set** if both `HasMacroNetworkAccess` and `HasMacroProcessSpawn`.
* `HasMacroPersistenceToOfficeStartup(f)` — Copies templates/add-ins. **Set** on file ops to Word startup.
* `HasMacroClipboardAccess(f)` — Reads clipboard. **Set** if `DataObject.GetFromClipboard`.
* `HasMacroVbeSelfModifying(f)` — Writes to its own VBA project. **Set** if interacting with `VBE` object model.
* `MacroSigned(f)` / `MacroSignatureValid(f)` — VBA project signed. **Set** if signature present & valid.
* `MacroCallsWmi(f)` — WMI via `GetObject("winmgmts:...")`. **Set** if present.
* `MacroUsesDnsTxtExfil(f)` — DNS exfil patterns. **Set** if `nslookup` calls or COM DNS objects used.
* `MacroHasSuspiciousAutoText(f)` — AutoText building malicious fields. **Set** by template/field analysis.

---

## 19) PDF-Specific

* `PdfHasJavaScript(f)` — Embedded JS. **Set** if `/JavaScript` or `/AA` dictionaries.
* `PdfHasOpenAction(f)` — Auto-run action. **Set** if `/OpenAction` present.
* `PdfHasLaunchAction(f)` — External launch. **Set** if `/Launch` action.
* `PdfHasEmbeddedFiles(f)` — File attachments. **Set** if `/EmbeddedFiles`.
* `PdfHasUrlActions(f)` — URI actions. **Set** if `/URI`.
* `PdfUsesXfa(f)` — XFA forms. **Set** if `/XFA` present.

---

## 20) Excel/PowerPoint-Specific

* `HasXlm4Macro(f)` — Excel 4.0 macro sheets. **Set** if `Macro` sheets or `xlm` functions present.
* `HasHiddenSheets(f)` — Hidden/very hidden sheets. **Set** by sheet flags.
* `HasExternalLinks(f)` — Pulls data from external sources. **Set** if external link tables exist.
* `PptHasActionButtonMacro(f)` — Action buttons invoking macros. **Set** via slide object actions.
* `OfficeUsesRemoteTemplate(f)` — External template (generic). **Set** if RELS point outward.
* `OfficeEmbeddedPackageExecutable(f)` — Embedded executable in Office file. **Set** if OLE `Package` contains PE.

---

## 21) Archive/Installer Abuse

* `ArchiveContainsExecutable(f)` / `ArchiveContainsScript(f)` — **Set** after enumerating members.
* `ArchiveIsPasswordProtected(f)` — **Set** via archive flags.
* `ArchiveDoubleExtensionMembers(f)` — `invoice.pdf.exe`. **Set** by filename analysis.
* `ArchiveBombHeuristic(f)` — Decompression ratio extreme. **Set** if size ratio exceeds threshold.
* `MsiRunsCustomAction(f)` — MSI with custom actions. **Set** if installer tables define external commands.

---

## 22) Credential & Account Abuse

* `ReadsSamDatabase(f)` — Windows SAM access. **Set** by file open handles.
* `AccessesBrowserCookiesAndLogins(f)` — Reads browser credential DBs. **Set** by file access paths and DPAPI calls.
* `CapturesClipboard(f)` — Clipboard monitoring. **Set** by APIs.
* `HooksKeyboard(f)` — Keylogger. **Set** if low-level keyboard hooks registered.
* `QueriesCloudImds(f)` — AWS/GCP/Azure metadata. **Set** if HTTP calls to IMDS endpoints.

---

## 23) Classification Helpers

* `IsSuspicious(f)` — Generic suspicion. **Set** by rule combinations (example rules below).
* `IsMalicious(f)` — Confirmed malicious. **Set** if high-confidence chain (e.g., download+execute + C2 + persistence).
* `IsPua(f)` — Potentially unwanted. **Set** if grayware patterns match (adware, bundlers).
* `IsBenignTooling(f)` — Known admin tool. **Set** if hash/vendor whitelisted.

---

# Example Rule Skeletons

* **Malicious macro downloader**
  `IsWord(f) ∧ HasMacros(f) ∧ (HasMacroNetworkAccess(f) ∨ ContainsDdeField(f)) ∧ (HasMacroProcessSpawn(f) ∨ WritesToTempExecutable(f)) → IsSuspicious(f)`

* **Ransomware behavior**
  `EncryptsManyFiles(f) ∧ DeletesShadowCopies(f) ∧ DropsRansomNote(f) → IsMalicious(f)`

* **Credential theft**
  `SpawnsPowerShell(f) ∧ ReadsLsassMemory(f) → IsSuspicious(f)`

* **Lateral movement**
  `UsesWmiForExec(f) ∧ UsesSmb(f) ∧ CreatesService(f) → IsSuspicious(f)`

* **High-risk unsigned loader**
  `IsPe(f) ∧ ¬IsSigned(f) ∧ (CreatesRemoteThread(f) ∨ AllocatesRWXMemory(f)) ∧ BeaconingPattern(f) → IsSuspicious(f)`

* **User-assisted attack**
  `UserEnabledMacros(u,f) ∧ HasAutoExecMacro(f) ∧ HasMacroDownloadAndExecute(f) → IsMalicious(f)`

* **Archive trap**
  `IsArchive(f) ∧ ArchiveIsPasswordProtected(f) ∧ ArchiveContainsExecutable(f) ∧ SourceIsEmailAttachment(f) → IsSuspicious(f)`

---

### Future work

* **Scoring**
  * Let `IsSuspicious(f)` be driven by a score threshold combining **static (S)** and **dynamic (D)** signals with tunable weights, while `IsMalicious(f)` requires at least one **ground truth chain** (e.g., download→execute→C2 **or** ransomware triad).
* **Temporal windows**: add time-aware conditions when chaining behaviors (e.g., “within 2 minutes of `UserEnabledMacros`”).

## Inference rules

Each rule is written in a compact logic style:

* **Syntax:** `Condition1 ∧ Condition2 ∧ (Alt1 ∨ Alt2) ∧ ¬Neg → DerivedPredicate   {level: Intermediary|Final, confidence: low|med|high}`
* **Time/window:** `Within(T)` means events occur inside the same time window.
* **Note:** Names match (or extend) the predicate catalog you already have; all `Derived*` predicates are **intermediary** unless marked as **Final**.

> You don’t have to implement every rule at once; start with the categories that fit your telemetry best (Office parsing, FS/Process/Network, Registry/Tasks, etc.), then add more.

---

## A) Office / Word Macro Chains

**Intermediary**

1. `IsWord(f) ∧ HasMacros(f) → OfficeWithMacros(f) {level: Intermediary, confidence: high}`
2. `OfficeWithMacros(f) ∧ (HasAutoExecMacro(f) ∨ ContainsDdeField(f)) → MacroAutoExecCapable(f) {Intermediary, high}`
3. `OfficeWithMacros(f) ∧ HasMacroObfuscation(f) → MacroObfuscated(f) {Intermediary, med}`
4. `OfficeWithMacros(f) ∧ HasMacroNetworkAccess(f) → MacroNetworkEnabled(f) {Intermediary, high}`
5. `OfficeWithMacros(f) ∧ HasMacroFileWrite(f) → MacroWritesFiles(f) {Intermediary, high}`
6. `OfficeWithMacros(f) ∧ HasMacroProcessSpawn(f) → MacroSpawnsProcesses(f) {Intermediary, high}`
7. `OfficeWithMacros(f) ∧ HasMacroPowerShellInvocation(f) → MacroInvokesPowerShell(f) {Intermediary, high}`
8. `IsDocm(f) ∧ ContainsExternalTemplateRef(f) → OfficeRemoteTemplate(f) {Intermediary, med}`
9. `OfficeWithMacros(f) ∧ HasHiddenVbaModules(f) → MacroHiddenModules(f) {Intermediary, med}`
10. `OfficeWithMacros(f) ∧ MacroSigned(f) ∧ ¬MacroSignatureValid(f) → MacroSignatureTampered(f) {Intermediary, high}`
11. `IsExcel(f) ∧ HasXlm4Macro(f) → ExcelXlmMacroPresent(f) {Intermediary, high}`
12. `IsWord(f) ∧ OfficeEmbeddedPackageExecutable(f) → OfficeEmbedsExecutable(f) {Intermediary, med}`
13. `IsWord(f) ∧ HasMacroPersistence(f) → MacroPersistenceBehavior(f) {Intermediary, high}`
14. `IsWord(f) ∧ HasMacroExternalTemplate(f) → MacroExternalTemplateAbuse(f) {Intermediary, med}`

**Higher-order Intermediaries**

15. `MacroAutoExecCapable(f) ∧ (MacroNetworkEnabled(f) ∨ MacroInvokesPowerShell(f)) → DownloaderMacroBehavior(f) {Intermediary, high}`
16. `MacroSpawnsProcesses(f) ∧ MacroWritesFiles(f) → DropperMacroBehavior(f) {Intermediary, high}`
17. `MacroObfuscated(f) ∧ (MacroNetworkEnabled(f) ∨ MacroSpawnsProcesses(f)) → MacroStealthyDownloader(f) {Intermediary, med}`
18. `ExcelXlmMacroPresent(f) ∧ (ContainsUrl(f) ∨ TriesToAccessTheInternet(f)) → XlmDownloaderPattern(f) {Intermediary, med}`

**Final**

19. `DownloaderMacroBehavior(f) ∧ (DownloadsFromInternet(f) ∨ TriesToAccessTheInternet(f)) → IsSuspicious(f) {Final, high}`
20. `DropperMacroBehavior(f) ∧ DropsAndExecutes(f) → IsSuspicious(f) {Final, high}`
21. `MacroAutoExecCapable(f) ∧ MacroPersistenceBehavior(f) ∧ (MacroInvokesPowerShell(f) ∨ MacroNetworkEnabled(f)) → IsSuspicious(f) {Final, high}`
22. `IsWord(f) ∧ HasMacros(f) ∧ HasMacroDownloadAndExecute(f) ∧ UserEnabledMacros(u,f) → IsMalicious(f) {Final, high}`

---

## B) PDF & Document Exploitation Cues

**Intermediary**

23. `IsPdf(f) ∧ PdfHasJavaScript(f) → PdfWithJavaScript(f) {Intermediary, med}`
24. `IsPdf(f) ∧ (PdfHasOpenAction(f) ∨ PdfHasLaunchAction(f)) → PdfAutoActionCapable(f) {Intermediary, high}`
25. `IsPdf(f) ∧ PdfHasEmbeddedFiles(f) → PdfEmbedsFiles(f) {Intermediary, med}`
26. `IsPdf(f) ∧ PdfHasUrlActions(f) → PdfUrlInteraction(f) {Intermediary, med}`
27. `IsRtf(f) ∧ ContainsKnownExploitArtifacts(f) → RtfExploitArtifacts(f) {Intermediary, med}`
28. `IsWord(f) ∧ AbusesEquationEditor(f) → EqnedtAbuseIndicators(f) {Intermediary, med}`

**Final**

29. `PdfAutoActionCapable(f) ∧ (PdfWithJavaScript(f) ∨ PdfEmbedsFiles(f)) ∧ ContainsDownloaderCode(f) → IsSuspicious(f) {Final, high}`
30. `RtfExploitArtifacts(f) ∧ DropsAndExecutes(f) → IsSuspicious(f) {Final, high}`

---

## C) Archive / Container Tricks

**Intermediary**

31. `IsArchive(f) ∧ ArchiveIsPasswordProtected(f) → ArchivePasswordProtected(f) {Intermediary, high}`
32. `IsArchive(f) ∧ ArchiveContainsExecutable(f) → ArchiveContainsPE(f) {Intermediary, high}`
33. `IsArchive(f) ∧ ArchiveContainsScript(f) → ArchiveContainsScriptContent(f) {Intermediary, high}`
34. `IsArchive(f) ∧ ArchiveDoubleExtensionMembers(f) → ArchiveDoubleExtensionRisk(f) {Intermediary, med}`
35. `IsArchive(f) ∧ ArchiveBombHeuristic(f) → ArchiveBombSuspicion(f) {Intermediary, med}`

**Final**

36. `ArchivePasswordProtected(f) ∧ (ArchiveContainsPE(f) ∨ ArchiveContainsScriptContent(f)) ∧ SourceIsEmailAttachment(f) → IsSuspicious(f) {Final, high}`
37. `ArchiveDoubleExtensionRisk(f) ∧ SourceIsEmailAttachment(f) → IsSuspicious(f) {Final, med}`

---

## D) Script-Led Downloaders / Launchers

**Intermediary**

38. `IsScript(f) ∧ ContainsDownloaderCode(f) → ScriptDownloader(f) {Intermediary, high}`
39. `IsPowerShellScript(f) ∧ ContainsSuspiciousKeywords(f) → PsSuspiciousKeywords(f) {Intermediary, med}`
40. `IsHTA(f) ∧ ContainsUrl(f) → HtaUrlLauncher(f) {Intermediary, med}`
41. `IsVBScript(f) ∧ (ContainsUrl(f) ∨ ContainsBase64Blobs(f)) → VbsDownloaderPattern(f) {Intermediary, med}`
42. `IsScript(f) ∧ HasObfuscatedStrings(f) → ScriptObfuscated(f) {Intermediary, med}`

**Final**

43. `ScriptDownloader(f) ∧ DownloadsFromInternet(f) ∧ DropsAndExecutes(f) → IsMalicious(f) {Final, high}`
44. `ScriptObfuscated(f) ∧ TriesToAccessTheInternet(f) ∧ (SpawnsCmd(f) ∨ SpawnsPowerShell(f)) → IsSuspicious(f) {Final, high}`

---

## E) PE / Native Binary Behaviors

**Intermediary**

45. `IsPe(f) ∧ ¬IsSigned(f) ∧ HasHighEntropy(f) → PackedUnsignedBinary(f) {Intermediary, med}`
46. `IsPe(f) ∧ (CreatesRemoteThread(f) ∨ WritesProcessMemory(f) ∨ AllocatesRWXMemory(f)) → InjectionBehavior(f) {Intermediary, high}`
47. `IsPe(f) ∧ LoadsLibraryFromTemp(f) → LoadsTempLibrary(f) {Intermediary, med}`
48. `IsPe(f) ∧ ContainsDownloaderCode(f) → BinaryDownloaderTraits(f) {Intermediary, med}`
49. `IsPe(f) ∧ (SpawnsPowerShell(f) ∨ SpawnsCmd(f) ∨ SpawnsWscript(f)) → BinarySpawnsScripting(f) {Intermediary, med}`
50. `IsPe(f) ∧ DeletesShadowCopies(f) → BinaryDeletesShadows(f) {Intermediary, high}`
51. `IsPe(f) ∧ DisablesSecurityTools(f) → SecurityToolInterference(f) {Intermediary, high}`
52. `IsPe(f) ∧ UsesDirectSyscalls(f) → DirectSyscallIndicator(f) {Intermediary, med}`

**Final**

53. `InjectionBehavior(f) ∧ BeaconingPattern(f) → IsSuspicious(f) {Final, high}`
54. `PackedUnsignedBinary(f) ∧ BinaryDownloaderTraits(f) ∧ TriesToAccessTheInternet(f) → IsSuspicious(f) {Final, high}`
55. `SecurityToolInterference(f) ∧ (InjectionBehavior(f) ∨ BinaryDeletesShadows(f)) → IsMalicious(f) {Final, high}`

---

## F) Network / C2 / Beaconing

**Intermediary**

56. `TriesToAccessTheInternet(f) ∧ UsesHTTPSRequests(f) ∧ UsesSelfSignedTls(f) → SuspiciousTlsUse(f) {Intermediary, med}`
57. `BeaconingPattern(f) ∧ (ContainsIpLiteral(f) ∨ DnsQueriesDGA(f)) → BeaconingWithPoorOpsec(f) {Intermediary, med}`
58. `UsesDnsOnlyBeaconing(f) → DnsTunnelingSuspected(f) {Intermediary, med}`
59. `ConnectsToTor(f) ∧ BeaconingPattern(f) → TorBeaconing(f) {Intermediary, med}`
60. `UsesCloudStorageApi(f) ∧ UploadsLargeVolume(f) → CloudExfilPattern(f) {Intermediary, high}`
61. `DownloadsFromInternet(f) ∧ WritesToTempExecutable(f) → DownloadDropToTemp(f) {Intermediary, high}`

**Final**

62. `DownloadDropToTemp(f) ∧ DropsAndExecutes(f) → IsSuspicious(f) {Final, high}`
63. `BeaconingWithPoorOpsec(f) ∧ InjectionBehavior(f) → IsMalicious(f) {Final, high}`
64. `DnsTunnelingSuspected(f) ∧ ReadsManyDocs(f) → IsSuspicious(f) {Final, high}`
65. `CloudExfilPattern(f) ∧ (CompressesBeforeUpload(f) ∨ ContainsBase64Blobs(f)) → IsMalicious(f) {Final, high}`

---

## G) Persistence Attainments

**Intermediary**

66. `CreatesRunKey(f) ∨ CreatesStartupShortcut(f) ∨ AbusesOfficeStartupFolders(f) → StartupPersistenceAttempt(f) {Intermediary, high}`
67. `CreatesScheduledTask(f) → TaskPersistenceAttempt(f) {Intermediary, high}`
68. `CreatesService(f) → ServicePersistenceAttempt(f) {Intermediary, high}`
69. `CreatesWmiEventSubscription(f) → WmiPersistenceAttempt(f) {Intermediary, high}`
70. `CreatesLaunchAgent(f) ∨ CreatesLaunchDaemon(f) → MacLaunchPersistenceAttempt(f) {Intermediary, high}`
71. `CreatesCronJob(f) ∨ CreatesSystemdService(f) → LinuxPersistenceAttempt(f) {Intermediary, high}`

**Higher-order Intermediary**

72. `(StartupPersistenceAttempt(f) ∨ TaskPersistenceAttempt(f) ∨ ServicePersistenceAttempt(f) ∨ WmiPersistenceAttempt(f)) → PersistenceAchieved(f) {Intermediary, high}`

**Final**

73. `PersistenceAchieved(f) ∧ (BeaconingPattern(f) ∨ TriesToAccessTheInternet(f)) → IsSuspicious(f) {Final, high}`
74. `PersistenceAchieved(f) ∧ SecurityToolInterference(f) → IsMalicious(f) {Final, high}`

---

## H) Privilege & Credential Access

**Intermediary**

75. `RequestsUacElevation(f) ∧ DropsAndExecutes(f) → PotentialUacBypassAttempt(f) {Intermediary, med}`
76. `AcquiresSeDebugPrivilege(f) ∧ (ReadsLsassMemory(f) ∨ WritesProcessMemory(f)) → CredentialAccessAttempt(f) {Intermediary, high}`
77. `ReadsLsassMemory(f) ∧ (UploadsLargeVolume(f) ∨ CompressesBeforeUpload(f)) → CredentialDumpExfilPattern(f) {Intermediary, high}`
78. `DropsKernelDriver(f) ∨ LoadsKernelDriver(f) → KernelActivity(f) {Intermediary, med}`

**Final**

79. `CredentialAccessAttempt(f) ∧ BeaconingPattern(f) → IsMalicious(f) {Final, high}`
80. `KernelActivity(f) ∧ DisablesSecurityTools(f) → IsMalicious(f) {Final, high}`

---

## I) Ransomware Triad & Precursor Signals

**Intermediary**

81. `MassFileModification(f) ∧ HasHighEntropy(f) → MassEncryptionSuspected(f) {Intermediary, high}`
82. `DeletesShadowCopies(f) ∧ StopsServicesRelatedToBackups(f) → BackupDestructionPattern(f) {Intermediary, high}`
83. `DropsRansomNote(f) → RansomNotePresent(f) {Intermediary, high}`

**Final**

84. `MassEncryptionSuspected(f) ∧ BackupDestructionPattern(f) ∧ RansomNotePresent(f) → IsMalicious(f) {Final, very-high}`
85. `MassEncryptionSuspected(f) ∧ BeaconingPattern(f) → IsSuspicious(f) {Final, high}`

---

## J) Lateral Movement & Remote Exec

**Intermediary**

86. `UsesWmiForExec(f) ∧ UsesSmb(f) → WmiSmbLateralMovement(f) {Intermediary, high}`
87. `UsesRemoteServiceCreation(f) ∧ UsesSmb(f) → RemoteServiceLateral(f) {Intermediary, high}`
88. `UsesWinRm(f) ∧ (EnumeratesAd(f) ∨ ScansNetwork(f)) → AdminRemoteOpsPattern(f) {Intermediary, med}`
89. `UsesPsExecLike(f) → PsExecStyleMovement(f) {Intermediary, high}`

**Final**

90. `(WmiSmbLateralMovement(f) ∨ RemoteServiceLateral(f) ∨ PsExecStyleMovement(f)) ∧ CredentialAccessAttempt(f) → IsMalicious(f) {Final, high}`
91. `AdminRemoteOpsPattern(f) ∧ BeaconingPattern(f) → IsSuspicious(f) {Final, high}`

---

## K) Exfiltration / Espionage

**Intermediary**

92. `ReadsManyDocs(f) ∧ CompressesBeforeUpload(f) → PrepForExfil(f) {Intermediary, high}`
93. `PrepForExfil(f) ∧ UploadsLargeVolume(f) → ExfilRunning(f) {Intermediary, high}`
94. `AccessesBrowserCredentialStores(f) ∧ UploadsLargeVolume(f) → BrowserCredExfilPattern(f) {Intermediary, high}`
95. `ScreenshotsTaken(f) ∧ UploadsLargeVolume(f) → ScreenExfilPattern(f) {Intermediary, med}`

**Final**

96. `ExfilRunning(f) ∧ (BeaconingPattern(f) ∨ UsesCloudStorageApi(f)) → IsMalicious(f) {Final, high}`
97. `BrowserCredExfilPattern(f) → IsMalicious(f) {Final, high}`

---

## L) Anti-Analysis & Evasion

**Intermediary**

98. `ChecksSandboxArtifacts(f) ∧ DetectsDebugger(f) → AntiAnalysisStack(f) {Intermediary, med}`
99. `DelaysExecutionLong(f) ∧ BeaconingPattern(f) → StagedBeaconing(f) {Intermediary, med}`
100. `UsesParentPidSpoofing(f) ∧ InjectionBehavior(f) → CovertExecutionPattern(f) {Intermediary, high}`
101. `EncryptsConfiguration(f) ∧ (DirectSyscallIndicator(f) ∨ UnhooksNtdll(f)) → StealthConfigLoader(f) {Intermediary, med}`

**Final**

102. `(AntiAnalysisStack(f) ∨ StealthConfigLoader(f)) ∧ BeaconingPattern(f) → IsSuspicious(f) {Final, high}`
103. `CovertExecutionPattern(f) ∧ SecurityToolInterference(f) → IsMalicious(f) {Final, high}`

---

## M) Email / Phishing Context

**Intermediary**

104. `SourceIsEmailAttachment(f) ∧ HasMismatchedDisplayNameAndAddress(f) → SuspiciousSender(f) {Intermediary, med}`
105. `SourceIsEmailAttachment(f) ∧ HasSuspiciousAttachment(f) → RiskyAttachmentContext(f) {Intermediary, high}`
106. `IsPhishingEmail(f) ∧ LinksToCredentialHarvestingSite(f) → PhishToCredHarvest(f) {Intermediary, high}`
107. `AttachmentHasMOTW(f) ∧ MarkOfTheWeb(f) → InternetOriginCorroborated(f) {Intermediary, high}`

**Final**

108. `RiskyAttachmentContext(f) ∧ (DownloaderMacroBehavior(f) ∨ ScriptDownloader(f) ∨ ArchiveContainsPE(f)) → IsSuspicious(f) {Final, high}`
109. `PhishToCredHarvest(f) ∧ UserDoubleClicked(u,f) → IsSuspicious(f) {Final, high}`

---

## N) Reputation, Signing & MOTW

**Intermediary**

110. `IsSigned(f) ∧ SignatureValid(f) ∧ SignedByKnownVendor(f) → StrongPublisherTrust(f) {Intermediary, high}`
111. `MarkOfTheWeb(f) ∧ SourceIsEmailAttachment(f) → InternetDeliveredAttachment(f) {Intermediary, high}`
112. `HashInThreatIntel(f) → KnownBadHash(f) {Intermediary, very-high}`
113. `HashInKnownGood(f) → KnownGoodHash(f) {Intermediary, very-high}`

**Final (Suppressors & Escalators)**

114. `KnownBadHash(f) → IsMalicious(f) {Final, very-high}`
115. `StrongPublisherTrust(f) ∧ ¬(InjectionBehavior(f) ∨ BeaconingPattern(f) ∨ PersistenceAchieved(f)) → LikelyBenign(f) {Final, high}`
116. `InternetDeliveredAttachment(f) ∧ (MacroAutoExecCapable(f) ∨ ScriptDownloader(f)) → IsSuspicious(f) {Final, high}`

---

## O) User-Action Coupling (Behavioral Path)

**Intermediary**

117. `UserEnabledMacros(u,f) ∧ OfficeWithMacros(f) → UserTriggeredMacroExecution(f) {Intermediary, high}`
118. `UserDownloadedFrom(u,f,src) ∧ MarkOfTheWeb(f) → UserDownloadedFromInternet(f) {Intermediary, high}`
119. `UserRanAsAdmin(u,f) ∧ RequestsUacElevation(f) → ConfirmedElevation(f) {Intermediary, high}`

**Final**

120. `UserTriggeredMacroExecution(f) ∧ DownloaderMacroBehavior(f) → IsSuspicious(f) {Final, high}`
121. `UserDownloadedFromInternet(f) ∧ (ArchiveContainsPE(f) ∨ ScriptDownloader(f) ∨ OfficeEmbedsExecutable(f)) → IsSuspicious(f) {Final, med}`
122. `ConfirmedElevation(f) ∧ PersistenceAchieved(f) → IsMalicious(f) {Final, high}`

---

## P) Cross-File / Campaign Correlation

**Intermediary**

123. `(BeaconingPattern(f1) ∧ BeaconingPattern(f2) ∧ SameC2Family(f1,f2)) → ClusteredC2Campaign(f1,f2) {Intermediary, high}`
124. `SharedDroppers(f1,f2) ∧ SimilarPersistenceKeys(f1,f2) → ClusteredPersistenceCampaign(f1,f2) {Intermediary, med}`
125. `OfficeRemoteTemplate(f) ∧ MultipleHostsAffected() → WidespreadTemplateAbuse(f) {Intermediary, med}`

**Final**

126. `ClusteredC2Campaign(f1,f2) ∨ ClusteredPersistenceCampaign(f1,f2) → IsMaliciousCampaign() {Final, high}`

---

## Q) OS-Specific Persistence & Abuse (macOS/Linux)

**Intermediary**

127. `CreatesLaunchAgent(f) ∨ CreatesLaunchDaemon(f) ∨ LoadsKernelExtension(f) → MacPersistenceOrKernel(f) {Intermediary, high}`
128. `CreatesSystemdUserService(f) ∨ ModifiesSudoers(f) ∨ CreatesSetuidBinary(f) → LinuxElevatedPersistence(f) {Intermediary, high}`

**Final**

129. `MacPersistenceOrKernel(f) ∧ BeaconingPattern(f) → IsSuspicious(f) {Final, high}`
130. `LinuxElevatedPersistence(f) ∧ CloudExfilPattern(f) → IsMalicious(f) {Final, high}`

---

## R) Installers / MSI

**Intermediary**

131. `IsInstaller(f) ∧ MsiRunsCustomAction(f) → InstallerCustomActions(f) {Intermediary, med}`
132. `InstallerCustomActions(f) ∧ (BinarySpawnsScripting(f) ∨ DownloadsFromInternet(f)) → InstallerDownloadsOrScripts(f) {Intermediary, med}`

**Final**

133. `InstallerDownloadsOrScripts(f) ∧ PersistenceAchieved(f) → IsSuspicious(f) {Final, high}`

---

## S) LNK / Shortcut Abuse

**Intermediary**

134. `IsLnk(f) ∧ IsShortcutAbuseCandidate(f) → LnkAbusePattern(f) {Intermediary, high}`
135. `LnkAbusePattern(f) ∧ (TargetsScriptOrBinary(f) ∨ HasObfuscatedArguments(f)) → LnkStealthLauncher(f) {Intermediary, med}`

**Final**

136. `LnkStealthLauncher(f) ∧ DownloadDropToTemp(f) → IsSuspicious(f) {Final, high}`

---

## T) False-Positive Suppression & Benign Profiling

**Intermediary**

137. `StrongPublisherTrust(f) ∨ KnownGoodHash(f) → BenignStrongSignals(f) {Intermediary, very-high}`
138. `IsPe(f) ∧ SignatureValid(f) ∧ SignedByKnownVendor(f) ∧ FrequentEnterpriseUsage(f) → EnterpriseBaselineTool(f) {Intermediary, high}`
139. `IsScript(f) ∧ DevToolsPathContext(f) ∧ ¬(TriesToAccessTheInternet(f) ∨ DropsAndExecutes(f)) → LikelyDevScript(f) {Intermediary, med}`

**Final**

140. `BenignStrongSignals(f) ∧ ¬(PersistenceAchieved(f) ∨ InjectionBehavior(f) ∨ BeaconingPattern(f)) → LikelyBenign(f) {Final, very-high}`
141. `EnterpriseBaselineTool(f) ∧ HashInKnownGood(f) → LikelyBenign(f) {Final, very-high}`

---

## U) Composite Finalizers (Global Aggregation)

142. `(DownloaderMacroBehavior(f) ∨ ScriptDownloader(f) ∨ BinaryDownloaderTraits(f)) ∧ (TriesToAccessTheInternet(f) ∨ DownloadsFromInternet(f)) → IsSuspicious(f) {Final, high}`
143. `(InjectionBehavior(f) ∨ CovertExecutionPattern(f)) ∧ (BeaconingPattern(f) ∨ SuspiciousTlsUse(f)) → IsMalicious(f) {Final, high}`
144. `PersistenceAchieved(f) ∧ (BeaconingPattern(f) ∨ ExfilRunning(f)) → IsMalicious(f) {Final, high}`
145. `IsSuspicious(f) ∧ DownloadsFromInternet(f) ∧ DropsAndExecutes(f) → IsMalicious(f) {Final, high}`
146. `IsSuspicious(f) ∧ (KnownBadHash(f) ∨ HashInThreatIntel(f)) → IsMalicious(f) {Final, very-high}`
147. `IsSuspicious(f) ∧ (RemoteServiceLateral(f) ∨ WmiSmbLateralMovement(f)) → IsMalicious(f) {Final, high}`
148. `IsSuspicious(f) ∧ UserRanAsAdmin(u,f) ∧ PersistenceAchieved(f) → IsMalicious(f) {Final, high}`
149. `IsSuspicious(f) ∧ AntiAnalysisStack(f) ∧ DirectSyscallIndicator(f) → IsMalicious(f) {Final, high}`
150. `IsSuspicious(f) ∧ (LinuxElevatedPersistence(f) ∨ MacPersistenceOrKernel(f)) → IsMalicious(f) {Final, high}`

---

## V) Time-Windowed Rule Variants (optional but powerful)

151. `UserEnabledMacros(u,f) ∧ HasAutoExecMacro(f) ∧ DownloadsFromInternet(f) ∧ Within(5m) → IsMalicious(f) {Final, high}`
152. `WritesToTempExecutable(f) ∧ DropsAndExecutes(f) ∧ BeaconingPattern(f) ∧ Within(2m) → IsMalicious(f) {Final, high}`
153. `CreatesRunKey(f) ∧ TriesToAccessTheInternet(f) ∧ ¬UserInteractionWithin(10m) → IsSuspicious(f) {Final, high}`

---

## W) Confidence Escalators & De-escalators

154. `IsSuspicious(f) ∧ MultipleHostsAffected() → EscalatePriority(f) {Intermediary, high}`
155. `LikelyBenign(f) ∧ (MarkOfTheWeb(f) ∨ InternetDeliveredAttachment(f)) → RecheckWithSandbox(f) {Final, med}`
156. `LikelyBenign(f) ∧ (UnusualNewBehaviorDetected(f)) → ReassessBaseline(f) {Final, med}`

---

### Explanation

**`{Intermediary, high}`** means:

* **Intermediary** → the rule produces a **mid‑stage fact** (a building block), not a final verdict.

  * Example: `MacroSpawnsProcesses(f)` is something later rules can chain on; it doesn’t, by itself, label a file malicious.

* **high** → an **estimated confidence/weight** you can use when scoring or prioritizing. It says “when this rule fires, it is a strong signal.”

---

## Why split “level” and “confidence”?

* **Level** indicates how you should use the fact:

  * **Intermediary**: compose with other facts; show in explanations; feed into higher‑order rules.
  * **Final**: a decision point such as `IsSuspicious(f)` or `IsMalicious(f)` that you can alert on or act upon.

* **Confidence** is a weight for scoring/triage. It’s **not necessarily a probability**; it’s an ordinal strength you can map to numbers.

---

## Advaced mapping: numeric instead of levels

If you want to compute scores:

* `very-high` → 0.95
* `high` → 0.80
* `med` → 0.60
* `low` → 0.30

You can then combine signals like this (common choices):

* **AND** chains: `min(c1, c2, …)` or product (`∏ ci`)
* **OR** alternatives: `max(c1, c2, …)`
* **Multiple independent supports** for the same conclusion: `1 − ∏ (1 − ci)`

Set thresholds, e.g., `score ≥ 0.8 → IsSuspicious`, `score ≥ 0.93 → IsMalicious`, and keep “hard” rules that override scores (e.g., known-bad hash).

---

## Tiny example

Rule fires:

```
OfficeWithMacros(f) → MacroSpawnsProcesses(f)   {Intermediary, high}
```

Interpretation: “We asserted `MacroSpawnsProcesses(f)` as an **intermediary** fact, with a **high** weight (e.g., 0.80).”

A later rule might be:

```
DownloaderMacroBehavior(f) ∧ DropsAndExecutes(f) → IsSuspicious(f)   {Final, high}
```

This one yields a **final** verdict you can alert on, again with a strong confidence.

---

**TL;DR**:

* **Intermediary/Final** tells you *what kind of conclusion* the rule produces.
* **low/med/high/very‑high** tells you *how strong that conclusion* should count in scoring and triage.


---

### Notes on Implementation

* **Intermediary predicates** like `DownloaderMacroBehavior(f)`, `PersistenceAchieved(f)`, `InjectionBehavior(f)` act as **hubs**; they simplify final decision rules and make explanations clearer.
* Add a **scoring overlay** (optional): Each satisfied condition contributes to a confidence score; final states (`IsSuspicious`, `IsMalicious`, `LikelyBenign`) can be thresholds on that score **or** triggered by “hard” chains (e.g., Ransomware triad).
* Include **provenance tags** with each fired rule (which sensors/observations contributed) to support analyst explainability.