# AGENTS.md — Guidance for Code Agents

## Roadmap
1. Provide a general-access login page that preserves the link a visitor used to arrive.
2. Implement user management so only approved users may upload through the browser.
3. Create simple upload and download pages that follow the design philosophy of [motherfuckingwebsite](https://motherfuckingwebsite.com/).
4. Future: randomize stored filenames for privacy.

## Setup
Use the helper script to create a virtual environment, install
dependencies and launch the development server:

```bash
./scripts/run.sh
```

To run the test suite:

```bash
source .venv/bin/activate
pip install -r app/requirements.txt pytest
pytest
```
