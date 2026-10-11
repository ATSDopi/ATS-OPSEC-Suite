# ATS-OPSEC-Suite — Cahier des charges (v2, enrichi)

> **État v0.2+ (implémenté)** : TUI complet + moteur `.aos` v1 (Argon2id →
> HKDF → STREAM chunked, **8 AEAD en cascade ordonnée libre** : XChaCha20-
> Poly1305, AES-256-GCM, AES-128-GCM, AES-GCM-SIV, AES-256-EAX,
> Deoxys-II-256, Ascon-128, AEGIS-256 — en-tête authentifié par AAD),
> pack multi-fichiers/dossiers (tar streamé), KEM hybride X-Wing
> (X25519+ML-KEM-768) multi-destinataires, keyring, keyfiles,
> diceware+zxcvbn, shred multi-passes, TUI full-souris + drag & drop,
> CLI complet — **non audité**. Voir §7 pour le détail du shipped.

> Document de conception complet. Fusion de la spec initiale
> (`spécifications_de_la_suite_opsec_ultime.md`) et d'un brainstorming
> fonctionnel/technique poussé. Chaque feature est taggée par version cible.

**Légende** : `[v0.1]` MVP · `[v0.2]` cœur · `[v0.3]` avancé · `[stretch]` R&D

---

## 1. Vision & positionnement

Une suite OPSEC **fichier-centrée** (pas un verrouillage système) :
chiffrer, cacher, transférer et détruire des données spécifiques avec un
contrôle granulaire total — depuis un TUI « piece of art ».

**Constat de marché** : aucun outil existant ne combine ces quatre
piliers dans une interface unique :

| Outil | Crypto moderne | Post-quantique | Stégo | Air-gap | TUI |
|---|---|---|---|---|---|
| age / rage | ✅ | ❌ | ❌ | ❌ | ❌ |
| Picocrypt | ✅ (+RS, deniable) | ❌ | ❌ | ❌ | ❌ (GUI) |
| VeraCrypt | ✅ (volumes cachés) | ❌ | ❌ | ❌ | ❌ (GUI datée) |
| steghide / OpenStego | ❌ (crypto vieille) | ❌ | ✅ | ❌ | ❌ |
| gpg-tui | ❌ (wrapper) | ❌ | ❌ | ❌ | ✅ |
| **ATS-OPSEC-Suite** | ✅ cascade + STREAM | ✅ hybride | ✅ adaptatif + auto-analyse | ✅ QR fountain | ✅ |

**Différenciateurs killer** (personne ne les combine) :

1. Chiffrement **hybride post-quantique** X25519 + ML-KEM-768 (X-Wing)
   dans un format fichier — ni age, ni Picocrypt, ni VeraCrypt.
2. Pipeline complet dans un seul TUI : chiffrer → cacher en stégo →
   exfiltrer par QR animés → shredder la source.
3. **Auto-stéganalyse** intégrée (chi²/RS/entropie) avant/après embed.
4. Transfert air-gap par **QR animés + codes fountain RaptorQ**.
5. Mot de passe de contrainte + **écran leurre** (decoy dashboard).
6. Rapport forensique inversé : « ce qu'un attaquant trouverait » +
   score OPSEC global.

---

## 2. Modules fonctionnels

### 2.1 Moteur cryptographique (`opsec-core::crypto`)

**Spec initiale conservée et précisée :**

- Chiffrement en **cascade paramétrable** : N couches AEAD dans l'ordre
  choisi par l'utilisateur (`xchacha20, aes-256-gcm, aes-128-gcm,
  aes-256-gcm-siv, aes-256-eax, deoxys-ii-256, ascon-128, aegis-256`),
  clé indépendante HKDF par couche, nonce dérivé par couche+chunk.
  `[v0.2]` — champ `ciphers` sérialisé dans l'en-tête (rétrocompat
  v1 via le champ `suite`).
- **STREAM chunked** (modèle age) : chunks de 64 Kio à 1 Mio, AEAD par
  chunk, nonce = préfixe aléatoire ∥ compteur, flag `LAST` sur le chunk
  final. Jamais de fichier entier en RAM, résistance à la troncature.
  `[v0.1]` — règle absolue : **AES-GCM = nonce compteur strict**
  (réutilisation = catastrophique), XChaCha20 = nonce 192 bits aléatoire
  ou compteur.
- KDF `Argon2id` 100 % paramétrable (mémoire Kio, itérations, lanes,
  sel) + `argon2 bench` qui calibre ~1 s sur la machine cible `[v0.1]`.
- Post-quantique (standards NIST finaux) :
  - **ML-KEM-768** (FIPS 203) — toujours en **hybride** X25519+ML-KEM
    (X-Wing) : si l'un casse, l'autre tient. `[v0.2]`
  - **ML-DSA-65** (FIPS 204) — signature de containers. `[v0.3]`
  - **SLH-DSA** (FIPS 205) — signature hash-based « paranoid »
    (signatures lourdes : usage backup). `[stretch]`
- Déni plausible : volume caché dans l'espace libre aléatoire d'un
  volume leurre, en-tête caché chiffré indistinguable du bruit (schéma
  VeraCrypt). `[v0.3]`

**Ajouts du brainstorming :**

- **Format `.aos` auto-décrit** : magic `AOS1` + en-tête authentifié
  versionné (algo, params KDF, chunk size, flags) → `ats-opsec info`
  audite n'importe quel container. `[v0.1]`
- **Padding de taille** (option) : ciphertext arrondi à un palier pour
  masquer la taille réelle du clair (style Padmé). `[v0.2]`
- **Compression optionnelle avant chiffrement** (zstd) avec warning
  « fuite de longueur si clair prévisible ». `[v0.2]`
- **Gestionnaire de clés** local : trousseau scellé par mot de passe
  maître (Argon2id → AEAD), keygen X25519/Ed25519/ML-KEM/ML-DSA,
  fingerprint façon SSH + **randomart visuel**. `[v0.2]`
- **Shamir k-of-n** sur la clé maître (crates `sharks`/`vsss-rs`) +
  backup papier imprimable (base32 + QR). `[v0.3]`
- **Keyfiles** : n'importe quel fichier haché (BLAKE3) comme facteur
  d'auth additionnel. `[v0.2]`
- **Générateur de passphrase diceware** (wordlist EFF embarquée) +
  mesure d'entropie `zxcvbn`. `[v0.1]`
- **Wipe de l'original** après chiffrement (option `--secure-delete`).
  `[v0.1]`
- Verrouillage temporel (timelock par itérations VDF légères).
  `[stretch]`

### 2.2 TUI / UX (`opsec-tui`)

**Spec initiale conservée :**

- **Séquence de boot cinématique** : pluie matrix → logo ASCII qui se
  décode glyphe par glyphe → checklist d'init des modules (CSPRNG, probe
  OS, mémoire lockée, moteur crypto, hyperviseur) → barre de progression
  → transition. Skippable (touche) + `--no-anim` + auto-skip si non-TTY.
  `[v0.1]`
- Onglets navigables clavier, popups de confirmation, barres de
  progression, thème cyberpunk. `[v0.1]`
- Mode **Standard** (défauts ultra-sécurisés) / **Expert** (chaque
  variable exposée). Config sauvegardée dans
  `%APPDATA%/ats-opsec/config.toml` — version scellée par mot de passe
  maître `[v0.3]`.

**Ajouts du brainstorming :**

- **Dashboard** : carte profil système (OS, FS, AES-NI/AVX2, mlock,
  hyperviseur), jauge d'entropie, **score OPSEC global**, statut des
  modules. `[v0.1]`
- **Palette de commandes** (`Ctrl+P`, façon VS Code) : recherche fuzzy
  de toutes les actions. `[v0.2]`
- Explorateur de fichiers intégré (sélection multi-fichiers). `[v0.2]`
- Écran d'aide `?` listant tous les raccourcis ; touches vim (`hjkl`)
  optionnelles. `[v0.1]` / `[v0.2]`
- Thèmes : vert/ambre/cyan/rouge, accent configurable, respect
  `NO_COLOR`. `[v0.2]`
- **Panic key** configurable (ex. `Échap`×3) : verrouille l'UI, purge
  les secrets en RAM, affiche un **écran leurre** crédible. `[v0.3]`
- Progression temps réel des opérations (worker threads + channels —
  jamais de blocage du rendu). `[v0.1]`
- Effets shader-like via `tachyonfx` (glitch au déverrouillage, dissolve
  au shred). `[v0.2]`
- Preview image dans le terminal (`ratatui-image`, sixel/kitty) pour le
  module stégo. `[v0.3]`
- First-run wizard : mot de passe maître + bench Argon2 + génération de
  trousseau. `[v0.2]`

### 2.3 Probe OS & adaptation dynamique (`opsec-core::sys`)

- Scan au boot : OS, arch, features CPU (`AES-NI`, `AVX2`, `SSE4.2` via
  CPUID), bit hyperviseur CPUID, RAM totale, type de FS du cwd
  (NTFS/APFS/ext4/Btrfs), présence swap/hibernation. `[v0.1]`
- Options incompatibles **grisées avec explication** (jamais cachées).
  `[v0.1]`
- Mémoire : `mlock`/`mlockall`/`MADV_DONTDUMP` + `PR_SET_DUMPABLE` (Unix),
  `VirtualLock` (Windows). Statut affiché OK/DÉGRADÉ. `[v0.1]` →
  passage à `memsec`/`secure-types` `[v0.2]`
- Shredding adapté au FS : warning explicite SSD/TRIM/journal/CoW —
  **honnêteté forensique** (shred ≠ garanti sur SSD). `[v0.1]`

### 2.4 Stéganographie (`opsec-stego`)

- Payload **toujours** : compressé → chiffré (pipeline crypto core) →
  ressemble à du bruit blanc. `[v0.2]`
- **PNG LSB dispersé** : positions pseudo-aléatoires seedées par la clé
  (jamais séquentiel — détecté par zsteg/SPA/RS). `[v0.2]`
- **WAV PCM LSB** (`hound`). `[v0.2]`
- JPEG **DCT** (coefficients post-quantification, style F5 + matrix
  embedding). Pas de crate mature → module maison ou FFI mozjpeg.
  `[stretch]`
- **Analyseur de capacité** : octets max, % de pixels touchés, heatmap
  des bits modifiés. `[v0.2]`
- **Auto-stéganalyse** : tests chi², RS, entropie avant/après → indice
  de détectabilité affiché. Cible : ≤ 10-15 % des pixels. `[v0.3]`
- Split multi-carriers (payload éclaté sur N images via fountain).
  `[stretch]`
- Scrub EXIF/métadonnées du carrier. `[v0.2]`

### 2.5 Anti-forensics (`opsec-wipe`)

- Zéroisation `zeroize`/`Zeroizing` sur toutes les clés/passphrases.
  `[v0.1]`
- **Shredder** : N passes (0x00, 0xFF, aléatoire), fsync, rename
  aléatoire, truncate, unlink. Rapport détaillé. `[v0.1]`
- Wipe du free space (`cipher /w` équivalent). `[v0.3]`
- Mot de passe de contrainte (**duress**) : détruit les en-têtes ou
  ouvre le volume leurre. Pièges à respecter : le leurre doit être un
  vrai container plausiblement « usé », jamais de flag « mode duress »
  stocké. `[v0.3]`
- Clipboard auto-clear après N s. `[v0.2]`
- Horodatages forgés sur les sorties (mtime/atime plausibles).
  `[v0.2]`
- Mode RAM-only (jamais de temp sur disque). `[v0.2]`
- **Rapport forensique inversé** : métadonnées, journal USN,
  thumbnails, recent-files, swap → score de résidu. `[stretch]`

### 2.6 Transfert air-gap (`opsec-qr`)

- **TX** : payload chiffré → codes fountain **RaptorQ** (`raptorq`) →
  séquence de QR animés affichés dans le TUI (débit/taille réglables).
  `[v0.2]` — MVP : QR statique pour petits payloads `[v0.1]`
- **RX** : webcam (`nokhwa`) → décodage (`rqrr`) → réassemblage.
  `[v0.3]`
- Alternative audio FSK (minimodem-like). `[stretch]`
- Backup papier : clé → QR + base32 imprimable. `[v0.3]`

### 2.7 Honeyfiles & détection d'environnement

- **Canaris** : faux fichiers mots-de-passe piégés (watermark +
  callback optionnelle). `[v0.3]`
- Anti-VM/anti-debug : bit hyperviseur CPUID, uptime, nb CPU,
  `IsDebuggerPresent`/ptrace → **avertir l'utilisateur** (jamais
  d'auto-destruction façon malware). `[v0.2]`
- Dead man's switch local. `[stretch]`

### 2.8 CLI (`opsec-cli`) — parité TUI

```
ats-opsec                    # lance le TUI
ats-opsec encrypt <f> [-o x.aos] [--cipher xchacha20|aes256gcm|cascade]
              [--argon2-m KiB] [-t iters] [-p lanes] [--secure-delete]
              [--compress] [--pad]
ats-opsec decrypt <f.aos> [-o out] [--verify-only]
ats-opsec info <f.aos>       # dump en-tête (--json)
ats-opsec shred <f> [--passes N] [--zero]
ats-opsec stego embed|extract|analyze ...
ats-opsec qr tx|rx ...
ats-opsec probe              # rapport système (--json)
ats-opsec bench              # calibre Argon2id ~1s
ats-opsec keygen|keys ...    # trousseau [v0.2]
```

Sorties `--json` stables, exit codes propres, stdout = données /
stderr = logs. `[v0.1]`

---

## 3. Architecture

```
ats-opsec-suite/               # package unique → workspace au besoin
├── src/
│   ├── main.rs                # clap → dispatch (TUI par défaut)
│   ├── lib.rs
│   ├── crypto/                # engine AEAD, cascade, .aos, argon2, kem
│   ├── sys/                   # probe OS/CPUID/mlock/FS/hyperviseur
│   ├── stego/                 # (traits Carrier + impls v0.2)
│   ├── transfer/              # (QR v0.2)
│   ├── cli/                   # impls sous-commandes
│   └── tui/                   # app, boot, screens, widgets, theme
└── docs/  tests/  .github/workflows/ci.yml
```

Évolution prévue vers un workspace `crates/opsec-{core,stego,qr,wipe,
detect,keys,cli,tui}` quand le volume le justifiera — les modules sont
déjà découpés pour ça. **Zéro logique métier dans tui/cli.**

## 4. Stack & crates

| Rôle | Crate | Note |
|---|---|---|
| TUI | `ratatui` 0.29 + `crossterm` | standard absolu |
| Effets TUI | `tachyonfx` | v0.2 |
| AEAD | `chacha20poly1305`, `aes-gcm`, `aes-gcm-siv`, `eax`, `deoxys`, `ascon-aead`, `aegis`(pure-rust) | couches de cascade |
| Packaging | `tar` (stream) + `std::io::pipe` | multi-fichiers → `.aos` packed |
| KDF | `argon2`, `hkdf`, `sha2` | |
| PQ | `ml-kem` 0.3, `ml-dsa` 0.1, `slh-dsa` | RustCrypto pur Rust, non audités → hybride obligatoire |
| Clés | `x25519-dalek`, `ed25519-dalek` | |
| RAM | `zeroize`, `secrecy` → `memsec` | |
| RNG | `rand`/`rand_core` `OsRng` | jamais thread_rng pour les clés |
| Stégo | `image`, `png`, `hound` | v0.2 |
| QR | `qrcode`/`fast_qr`, `raptorq`, `rqrr`, `nokhwa` | v0.2 |
| CLI | `clap` 4 derive, `rpassword`, `zxcvbn` | |
| Divers | `serde`, `thiserror`, `anyhow`, `blake3`, `zstd`, `dirs` | |

## 5. Règles d'ingénierie sécurité

1. AEAD partout, jamais de déchiffrement non authentifié ; vérifier le
   tag **avant** d'écrire du clair (temp + rename).
2. Nonces : AES-GCM compteur strict ; jamais de réutilisation.
3. `OsRng` seul pour clés/nonces/sels.
4. Tout secret : `Zeroizing<T>`, portée minimale, mlock quand dispo.
5. Cascade = AEAD imbriqués par chunk (tags des deux couches vérifiés).
6. Leurre : indistinguabilité totale (mêmes primitives, timestamps
   crédibles, aucun marqueur interne).
7. Honnêteté : jamais « indétectable » — afficher les limites (SSD,
   juridictions où le déni n'est pas une défense).
8. KAT (vecteurs NIST/Wycheproof) en CI + `cargo audit` + lockfile
   commité.

## 6. Menaces & non-buts

- **Protège contre** : vol/lecture de fichiers au repos, analyse
  statistique de stégo, attaquant sans la passphrase, fuite via swap
  (mlock), troncature de containers.
- **Ne protège pas contre** : machine compromise à l'exécution
  (keylogger, mémoire lue à chaud), coercition physique dans les
  juridictions pénalisant le refus de clé (RIPA §49 UK, art. 434-15-2
  FR — le déni reste un pari forensique), mélange avec un environnement
  déjà surveillé.
- **Légal** : usage légitime assumé ; disclaimers dans README +
  SECURITY.md.

## 7. Roadmap

- **v0.1 ✅ shipped** — boot anim, TUI onglets/dashboard/probe réel,
  QR statique, tests + CI.
- **v0.2 ✅ shipped** — `.aos` v1 : Argon2id paramétrable (+bench) → HKDF →
  STREAM chunked XChaCha20 / AES-256-GCM / cascade, AAD sur en-tête
  signée, keyfiles BLAKE3, compression zstd, padding 4 Kio + jitter,
  X-Wing (X25519+ML-KEM-768) multi-destinataires, keyring `.pub/.sec`,
  diceware + zxcvbn, shred N passes + rename + unlink, CLI complet,
  TUI : modales de saisie masquée + workers de progression + onglets
  VAULT/KEYS/SHRED câblés sur le moteur.
- **v0.2+ ✅ shipped** — moteur généralisé : 8 AEAD exposés
  (XChaCha20-Poly1305, AES-256-GCM, AES-128-GCM, AES-GCM-SIV, AES-256-EAX,
  Deoxys-II-256, Ascon-128, AEGIS-256) en **cascade ordonnée libre** avec
  clé par couche et nonces dérivés ; pack multi-fichiers/dossiers en tar
  streamé (`packed:true` dans l'en-tête, extraction anti-path-traversal) ;
  TUI CRYPT repensé (TARGETS drag&drop multi, OPERATIONS encrypt/decrypt/
  audit, OPTIONS cliquables : auth passphrase↔recipients, couches AEAD
  réordonnables, compress/pad/shred-orig) ; KEYS accepte un `.aos`
  droppé → décryptage par clé ; CLI `encrypt` multi-input + `--cipher`
  liste.
- **v0.3** — stégo PNG/WAV dispersé + capacité + auto-analyse, QR fountain
  TX/RX (raptorq + webcam), sealed keyring (mot de passe maître),
  Shamir k-of-n + backup papier, volumes cachés + duress, ML-DSA
  signatures, wipe free space, tachyonfx, palette de commandes.
- **stretch** — DCT JPEG, SLH-DSA, timelock, audio FSK, rapport
  forensique inversé, plugins wasm.

## 8. Outillage Devin recommandé

Skills existantes couvrant le projet : `lang-rust`, `dev-cli`,
`dev-security`, `dev-testing`, `dev-ci-cd`, `dev-release`, `dev-git`,
`dev-docs`, `dev-code-quality`. Aucune installation requise ; si le TUI
devient massif, créer une skill `dev-tui` (patterns ratatui) via
`meta-skill-authoring`.
