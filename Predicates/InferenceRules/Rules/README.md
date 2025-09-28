# Inference rules

## File facts

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
