# blare-rs

Reproduction V1 d'un moteur AOT PE64 inspiré BLARE (user-mode + drivers kernel + UEFI).

## Crates
- `blare-cli`: CLI (`blare`) pour valider/rewrite/vérifier.
- `blare-cfg`: parsing/normalisation JSON Ghidra (`ExportCFG.java`).
- `blare-pe`: parsing/édition PE64, sections, reloc, `.pdata/.xdata`.
- `blare-ir`: IR arène indexée.
- `blare-lift`: lifting natif `iced-x86` + validation CFG/PE.
- `blare-rewrite`: relayout code, réencodage, remap relocs, reconstruction unwind.
- `blare-passes`: profils d'obfuscation robustes (`balanced`, `aggressive`, `sigbreaker`) et passes anti-analyse.
- `blare-module-ext`: couche dédiée à l'ingestion de modules COFF/objets (préparation module extension).

## Commandes
```bash
cargo run -p blare-cli -- validate-cfg --input input.bin --cfg cfg.json
cargo run -p blare-cli -- ingest-ghidra --input input.bin --cfg ghidra.json --output normalized.json --min-coverage 0.90 --strict
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.bal.bin --map out.bal.map.json --profile balanced --strict-unwind --rewrite-policy per-function
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.agg.bin --map out.agg.map.json --profile aggressive --seed 1337 --strict-unwind --rewrite-policy per-function --indirect-cf-probability 0.65
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.imp.bin --map out.imp.map.json --profile aggressive --strict-unwind --rewrite-policy per-function --import-protection
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.pre.bin --map out.pre.map.json --profile aggressive --strict-unwind --rewrite-policy per-function --anti-debug
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.obfep.bin --map out.obfep.map.json --profile aggressive --strict-unwind --rewrite-policy per-function --anti-debug --obscure-entry-point
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.nounwind.bin --map out.nounwind.map.json --profile balanced --rewrite-policy per-function --clear-unwind-info
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.sig.bin --map out.sig.map.json --profile sigbreaker --strict-unwind --rewrite-policy per-function --section-layout compact
cargo run -p blare-cli -- rewrite --input input.bin --cfg cfg.json --output out.compact.bin --map out.compact.map.json --profile balanced --strict-unwind --rewrite-policy module --section-layout compact
cargo run -p blare-cli -- verify-seh --input out.bin
cargo run -p blare-cli -- verify-unwind --input out.bin
cargo run -p blare-cli -- inspect --input out.bin --json
cargo run -p blare-cli -- export-cytoscape --input input.bin --cfg cfg.json --function main --output web/cfg-viewer/cfg_output.json
```

Commande utilitaire locale pour fixtures:
```bash
cargo run -p blare-cli -- seed-cfg --input input.exe --output cfg.json
```

## Pipeline fixtures
```bash
# auto: utilise Ghidra headless si disponible, sinon fallback seed-cfg
./scripts/build_fixtures.sh
./scripts/rewrite_fixtures.sh
./scripts/verify_structure.sh
./scripts/run_wine_compare.sh
```

Pipeline driver `.sys` (à partir d'un CFG Ghidra exporté):
```bash
./scripts/rewrite_driver.sh /path/to/driver.sys /path/to/driver.ghidra.json /tmp/driver.rewritten.sys /tmp/driver.map.json
```

Variables d'environnement utiles:
- `WINE_BIN` (default: `/Users/ordi/Downloads/lift/binary_rewriter/tools/wine/Wine Stable.app/Contents/Resources/wine/lib/wine/x86_64-unix/wine`)
- `WINEPREFIX_PATH` (default: `/Users/ordi/Downloads/lift/binary_rewriter/.wineprefix`)
- `LLVM_READOBJ` (default: `/opt/homebrew/opt/llvm/bin/llvm-readobj`)
- `USE_REAL_GHIDRA` (`auto|1|0`, default: `auto`) pour `scripts/build_fixtures.sh`
- `GHIDRA_HEADLESS` (default: `/opt/homebrew/opt/ghidra/libexec/support/analyzeHeadless`)
- `GHIDRA_SCRIPT_DIR` (default: `<workspace>/levo-main/ghidra_cfg`) pour `scripts/export_ghidra_cfg.sh`
- `GHIDRA_PROJECT_ROOT` (default: `/tmp/ghidra_proj_blare`) pour `scripts/export_ghidra_cfg.sh`

## Viewer CFG (HTML/JS)
Exporter un JSON "Function Explorer" (liste complète + graph par fonction):
```bash
cargo run -p blare-cli -- export-cytoscape --input tests/fixtures/bin/fixture_basic.exe --cfg tests/fixtures/cfg/fixture_basic.ghidra.normalized.json --output web/cfg-viewer/cfg_output.json
```

Mode statique (lecture JSON uniquement):
```bash
cd web/cfg-viewer
python3 -m http.server 8080
```

Puis ouvrir:
- `http://127.0.0.1:8080/index.html?cy=cfg_output.json`

Mode complet (obfuscation lancée depuis le site + comparaison side-by-side):
```bash
cd web/cfg-viewer
node server.js
```

Puis ouvrir:
- `http://127.0.0.1:8080/`

Le serveur expose:
- `POST /api/run-obfuscation`: lance `blare rewrite`, génère les JSON gauche/droite, remappe le CFG réécrit, puis renvoie la comparaison chargée.
- `POST /api/load-compare`: charge un couple `left/right` (+ map optionnelle) depuis des paths absolus/relatifs.
- `GET /api/last-run`: recharge automatiquement la dernière comparaison.
- `GET /api/config`: fournit les defaults (EXE/CFG + derniers paths).

Le viewer charge `Cytoscape.js` + `cytoscape-dagre` et fournit:
- liste/search des fonctions à gauche
- comparaison side-by-side de la même fonction (original vs obfusquée)
- mapping ancienne/nouvelle adresse pour la fonction sélectionnée
- panneau passes (`applied_passes`, `pass_stats`, profil, seed, rewritten bytes)
- graphes CFG orthogonaux avec nœuds rectangulaires et couleurs par type de flux:
  - vert: branche vraie
  - rouge: fallthrough / branche fausse
  - bleu: saut inconditionnel et appels
  - arête plus épaisse sur back-edge (boucles)
- coloration syntaxique dans les blocs (mnemonic, registres, immediates, adresses)

## Limites actuelles
- Cible `PE32+` uniquement (EXE/DLL/SYS/EFI x64).
- Le support unwind EH/UH/CHAININFO est implémenté, mais la précision dépend de la qualité des bornes CFG/xdata.
- Les passes cœur (`mba-nonlinear`, `opaque-one-way`, `opaque-path-explosion`) sont en fail-closed; les passes SigBreaker tournent en best-effort avec métriques de mutation/skips.
- Le profil `sigbreaker` reste actif en mode best-effort (passes toujours exécutées + métriques), impose `--section-layout compact` et applique une contrainte zero-bloat stricte sur le code réencodé (pas d'augmentation de la zone réécrite).
- La map inclut `obfuscation_profile`, `obfuscation_seed`, `applied_passes` et `pass_stats`.
- `--section-layout compact` réutilise `.text` (et `.reloc` si possible) in-place, garde les métadonnées unwind legacy intactes, exige `0` fonction fallback et `0` edge CFG direct non résolu.
- `ingest-ghidra` applique un seuil de couverture par défaut `--min-coverage 0.90`; `--strict` rejette le CFG si le lift détecte des fonctions fallback.
- En UEFI sans exception directory (`.pdata` vide), `verify-unwind` considère ce cas valide.
- Le profil `aggressive` active des passes de références/control-flow indirects via thunks + table `.blrthk`; `--indirect-cf-probability` (0.0–1.0, défaut `0.35`) contrôle le taux d'injection de l'indirection CFG.
- `--import-protection` active l'obfuscation IAT (imports nommés): hash DLL/fonction (FNV-1a), section `.blrimp` chiffrée XOR, patch des call-sites vers stubs injectés, puis zeroing des entrées IAT effectivement protégées.
- `--anti-debug` injecte un pré-stub `.blrpre` avant le vrai OEP: checks `PEB.BeingDebugged`, `PEB.NtGlobalFlag & 0x70`, heuristique timing `RDTSC`, scan de breakpoints `0xCC` sur les premiers octets de l'OEP.
- `--obscure-entry-point` ajoute une séquence exception-based au pré-stub (`INT3` + handler vectored qui redirige vers le vrai OEP). Ce mode est limité à `PeBinaryKind::UserMode`.
- `--clear-unwind-info` force `IMAGE_DIRECTORY_ENTRY_EXCEPTION = 0` en sortie et nettoie les sections `.blrxdt/.blrpdt` quand elles existent (utile en UEFI/kernel sans SEH).
