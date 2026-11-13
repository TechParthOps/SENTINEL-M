# Contributing to SENTINEL-M

## Principles (from the product spec — non-negotiable)

1. Never claim a threat was detected without evidence. Every alert references event IDs.
2. Never present simulated activity as real. Planned capabilities are labeled `planned`.
3. Never let an LLM execute unrestricted commands or rewrite its own rules.
4. Never break working functionality for new features.
5. No placeholder buttons, fake charts, or non-functional integrations.
6. Every important operation must be logged, auditable and testable.

## Workflow

1. Pick work from the phase roadmap (`research/THREAT_COVERAGE_MATRIX.md`).
2. Write/adjust tests first or alongside the implementation.
3. Keep changes surgical — do not rewrite modules to solve small problems.
4. Run the full verification before committing:
   ```powershell
   cd backend;  python -m pytest -q
   cd frontend; npm run build; npm test
   powershell -File scripts\smoke_test.ps1
   ```
5. Update `CHANGELOG.md`, `docs/REPORTS/` (phase report), and coverage data
   (`backend/app/coverage.json` + `research/THREAT_COVERAGE_MATRIX.md` together).
6. Commit with a descriptive message. Keep git history meaningful.

## Code conventions

- Backend: Python 3.11, FastAPI, type hints, docstrings on every module, no comments that
  restate code. Vendors-specific knowledge only in adapters; engines see canonical events.
- Frontend: TypeScript strict, functional components, store-per-domain (zustand), UI primitives
  in `components/ui.tsx`. No mock data in production paths.
- Detection rules: one JSON file per rule in `detection-rules/`, id pattern
  `AREA-NAME-NNN` (e.g. `HOST-PS-ATTACK-001`), mandatory `attack_ids` + `notes` fields.

## Security disclosures

See `SECURITY.md`. Do not open public issues for security defects.