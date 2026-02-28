# dwlabbind

BIND statement classes, parser, and CLI tools.

## Development layout

This repository uses a `src` layout:

```text
dwlabbind/
├─ pyproject.toml
├─ src/
│  ├─ dwlabbind/
│  └─ etc/
├─ tests/
└─ .vscode/
```

## Local development setup

1. Create and activate a virtual environment.
2. Install in editable mode (recommended for `src` layout projects):

```bash
python -m pip install -e . --no-build-isolation
```

3. Run the CLI module:

```bash
python -m dwlabbind.runner --help
```

If you prefer running without an editable install, export `PYTHONPATH=src`.
For VS Code, copy `.env.example` to `.env`.
