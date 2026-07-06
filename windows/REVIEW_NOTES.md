# REVIEW_NOTES — driver Windows (revue statique, PAS une preuve de correction)

> ⚠️ Le driver n'a **jamais été compilé ni chargé**. Cette revue statique liste
> ce qui **reste à valider** au premier build/chargement (Driver Verifier armé,
> snapshot VM). Elle ne prétend PAS que le driver est correct. Classes de bugs
> kernel passées en revue : IRQL, allocations non libérées, buffers non bornés,
> déréférencements non vérifiés, blocage/perf.

## Corrigé pendant la revue
- **Over-read `UNICODE_STRING`** (VssGuard) : `ImageFileName`/`CommandLine` ne sont
  pas garantis nul-terminés → copies bornées nul-terminées avant classification.
- **Whitelist par suffixe** → comparaison du **chemin d'image complet** (T2), sinon
  `evil\rsync.exe` serait exempté.
- **Préfixe de dossier trop laxiste** : `…\documents` matchait `…\documents2\…`.
  Corrigé : le caractère suivant le préfixe doit être `\` (ou fin de chemin).

## À VÉRIFIER au premier build/chargement (points d'attention)

### IRQL / contexte
- `CanarisDecide` : garde `KeGetCurrentIrql() == PASSIVE_LEVEL` + `!IRP_PAGING_IO`
  avant `FltGetFileNameInformation` (qui l'exige). **À confirmer** que les trois
  pré-callbacks s'exécutent bien à PASSIVE dans les cas testés (create : oui ;
  write/set-info : possible APC/DPC pour I/O asynchrone → on bail-out, donc ces
  I/O ne sont pas filtrées — **limite de couverture connue**, cf. §perf).
- `FAST_MUTEX` (`ExAcquireFastMutex`) exige ≤ APC_LEVEL : OK depuis PASSIVE.

### Allocations / libérations
- `CanarisAddEntry` : `entry` + `entry->Path.Buffer` libérés sur chemin d'erreur
  (`CanarisDupPath` échoue) — **à confirmer sous Driver Verifier (pool tracking)**.
- `CanarisIsWhitelisted` : `SeLocateProcessImageName` alloue `image`, libéré par
  `ExFreePool` sur tous les chemins — **à confirmer**.
- `CanarisClearList` à l'unload libère toutes les entrées — **à confirmer (fuite ?)**.
- `ExAllocatePool2(POOL_FLAG_NON_PAGED, …)` partout (pas `…WithTag` déprécié). OK.

### Buffers / validation d'entrée
- `CanarisPortMessage` : `InputBufferLength >= sizeof(CANARIS_CONFIG_MSG)` vérifié ;
  copie défensive sous `__try/__except`. `PathLength` borné dans `CanarisAddEntry`.
- `CanarisNotify` : copie bornée à `CANARIS_MAX_PATH`.

### Déréférencements
- `CanarisDecide` vérifie `nameInfo != NULL` après `FltGetFileNameInformation`.
- `CanarisIsProtected` : match préfixe dossier — **NB** : `RtlPrefixUnicodeString`
  matche `…\documents` comme préfixe de `…\documents2\…`. **À durcir** : exiger que
  le caractère suivant le préfixe soit `\` (sinon faux positif de sous-arbre).

### Blocage / performance (limites de conception, pas des bugs)
- `CanarisNotify` appelle `FltSendMessage` avec timeout **100 ms** depuis le
  pré-callback : sous forte charge d'accès protégés, ajoute de la latence. Envisager
  une file asynchrone (work item) si R8 dépasse le budget.
- **Paging I/O non filtré** (mmap writes) : un chiffrement via section mappée
  contournerait `IRP_MJ_WRITE`. Le blocage à `IRP_MJ_CREATE` (open) reste la
  première ligne. À documenter comme vecteur résiduel.
- `IRP_MJ_SET_INFORMATION` (rename/delete) : on inspecte la **source** ; un rename
  *entrant* dans un dossier protégé depuis l'extérieur n'est pas couvert.
- `gEnforce` lu/écrit sans verrou (BOOLEAN aligné) : bénin.

### Communication port
- Une seule connexion (`maxConnections = 1`), ACL admin via
  `FltBuildDefaultSecurityDescriptor(FLT_PORT_ALL_ACCESS)` (NF8/NF9).
- Course possible `Disconnect` vs `FltSendMessage` sur `gClientPort` : FltMgr
  sérialise en partie, mais **à surveiller** sous Driver Verifier.

## Recette de revue au chargement
1. Build (`vm/build_windows.ps1`) sans erreur ni warning bloquant.
2. `verifier /standard /driver Canaris.sys` armé, snapshot VM.
3. Charger (`fltmc load`), stresser (canary, rename, delete, VssGuard), décharger.
4. Aucune fuite pool (Driver Verifier), aucun BSOD, altitude 328000 visible.
5. Consigner dans `vm/evidence/windows_<date>/`.
