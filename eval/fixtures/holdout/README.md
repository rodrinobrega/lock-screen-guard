# Holdout fixtures

HTML files placed here are **not committed** (see `.gitignore`). They exist so a
reviewer — or a separate AI agent given only `expected.json` and the harness —
can write fresh attack variants the detector was never tuned on.

To add one, drop `name.html` here and add an entry to `holdout.json` next to it:

```json
{ "cases": [ { "id": "holdout/name", "file": "holdout/name.html", "expected": ["SCAM"] } ] }
```

`npm run eval` reports holdout results separately from the visible corpus.
