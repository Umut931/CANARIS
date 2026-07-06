# Protocole de validation Windows (VM WDK + Test Signing)

> **BLOQUANT pour la crédibilité du volet Windows.** Le minifilter (~1000 lignes)
> n'a **jamais été compilé ni chargé** dans l'environnement de dev (pas de WDK).
> Ce protocole le build, le charge et le teste. **Prendre un snapshot VM AVANT
> chaque chargement de driver** — un minifilter bugué peut BSOD.

## 0. Préparer la VM (une fois)

- Windows 10 1607+ / 11 x64, **VM dédiée** (jamais bare-metal).
- Visual Studio 2022 (« Développement Desktop C++ ») + **WDK** assorti au SDK.
- Désactiver **Secure Boot** (firmware de la VM).
- Désactiver **HVCI** : Sécurité Windows → Sécurité des appareils → Isolation du
  noyau → Intégrité de la mémoire = **Désactivé**.
- Activer **Test Signing** puis reboot :
  ```powershell
  bcdedit /set testsigning on
  shutdown /r /t 0
  ```
- **Snapshot VM « clean + testsigning »** ici.

## 1. Build (T-W1)

```powershell
powershell -ExecutionPolicy Bypass -File vm\build_windows.ps1 -Configuration Debug
```
Attendu : `windows\x64\Debug\Canaris.sys` + `CanarisSvc.exe`. En cas d'erreur de
compilation, corriger avant d'aller plus loin (voir `windows\REVIEW_NOTES.md`
pour les points d'attention connus).

## 2. Driver Verifier (obligatoire pendant tout le test)

```powershell
verifier /standard /driver Canaris.sys
shutdown /r /t 0
```
> **Snapshot VM « verifier armé »** avant le premier chargement.

## 3. Chargement du minifilter (T-W2, recette R3)

```powershell
sc create Canaris type= filesys binPath= "C:\chemin\Canaris.sys"
fltmc load Canaris
fltmc filters          # doit lister Canaris avec l'altitude 328000
```
**Attendu (R3)** : Canaris listé, **aucun BSOD**. Si BSOD → restaurer le snapshot,
analyser le minidump (`!analyze -v` sous WinDbg), corriger.

## 4. Configuration + service (T-W2.5)

```powershell
mkdir C:\ProgramData\Canaris -Force
"C:\CanarisDemo" | Out-File -Encoding ascii C:\ProgramData\Canaris\protected_dirs.txt
python common\canary_generator.py --target-dir C:\CanarisDemo --control-dir C:\ProgramData\Canaris --count 3
# canary_files.txt est écrit dans le control-dir (HORS de l'arbre protégé, T3)
# whitelist = CHEMINS D'EXÉCUTABLES complets (T2), un par ligne :
"C:\Windows\System32\notepad.exe" | Out-File -Encoding ascii C:\ProgramData\Canaris\whitelist.txt
.\x64\Debug\CanarisSvc.exe --console
```
**Attendu** : « Configuration poussee au minifilter » dans
`C:\ProgramData\Canaris\canaris_events.log`.

## 5. Blocage canary (T-W3, exigence F2.2)

```powershell
# depuis un process NON whitelisté (ex. un éditeur non listé) :
Add-Content C:\CanarisDemo\<canary>.pdf "x"    # -> Accès refusé (STATUS_ACCESS_DENIED)
```
**Attendu** : accès refusé + log `ALERTE CANARY/BLOCKED` + kill + snapshot VSS.
Contrôle : le process whitelisté (notepad.exe ci-dessus) peut accéder.

## 6. VssGuard — suppression VSS (T-W5, recette R5)

```powershell
vssadmin delete shadows /all      # ou : wmic shadowcopy delete
```
**Attendu (R5)** : alerte **priorité maximale immédiate** + (si enforce) création
du process bloquée (`STATUS_ACCESS_DENIED`). Log `ALERTE VSS-DELETE`.

## 7. Benchmark latence I/O (T-W6, recette R8 / NF1)

```powershell
diskspd -c1G -d30 -w50 C:\bench\test.dat      # filtre déchargé
fltmc load Canaris
diskspd -c1G -d30 -w50 C:\bench\test.dat      # filtre chargé
```
**Attendu (R8)** : surcoût < 5 %.

## 8. Déchargement

```powershell
fltmc unload Canaris
sc delete Canaris
verifier /reset ; shutdown /r /t 0
```

## Consigner les preuves

Copier les sorties (`fltmc filters`, logs, éventuels minidumps) dans
`vm/evidence/windows_<date>/` et cocher la matrice de `README.md`.
