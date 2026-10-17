# Pax filter workflow: history

Written by the nightly filter workflow (.github/workflows/filter-loop.yml on main).
`scoreboard/history.csv` has one row per run; `scoreboard/latest.md` explains the latest.
`state/` is what the workflow remembers between nights (homepage verdicts, checked
additions, held-back entries, published packs). Site names are kept gzipped or encoded.
