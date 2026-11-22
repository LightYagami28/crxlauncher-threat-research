# Revisione finding Codacy — crxlauncher-threat-research

Data: 2026-11-22. Fonte: API Codacy v3, `gh/LightYagami28/crxlauncher-threat-research`.
Metodo: `POST .../issues/overview` e `POST .../issues/search` con cursori, livelli Error/High/Warning/Info.

## Conteggi

| Livello | Totale |
| --- | ---: |
| High | 4 |
| Warning | 7 |
| Info | 51 |
| **Totale** | **62** |
| belowThreshold | 62 |
## Falsi positivi da verificare

- **`Prospector_pydocstyle` (49)** — le segnalazioni (D213, D406, D407, D413) chiedono di convertire docstring in stile Google (`Returns:`) allo stile NumPy (`Returns` + sottolineatura tratteggiata). La convenzione adottata nel progetto e' Google: e' un conflitto di convenzioni tra linter e codice, non un difetto.
- **`PyLintPython3_W0621` (4)** — "redefining name from outer scope" su nomi condivisi deliberatamente.
- **`Prospector_pyright` (3)** — diagnostica su import di dipendenze opzionali non risolte nell'ambiente di analisi.

## Finding reali

- `Lizard_ccn-medium` (2), `PyLintPython3_C1803` (2), `Prospector_vulture` (1): complessita' e codice non usato, da trattare in PR dedicate con i test del repo.
- `Agentlinter_consistency_referenced-files-exist` (1): da verificare il link segnalato.

Nessuna modifica a configurazioni o soglie; nessuna soppressione.

