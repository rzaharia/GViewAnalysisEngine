# GView Analysis Engine - File predicates

Here is the entire list of the predicates in a readable way.

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