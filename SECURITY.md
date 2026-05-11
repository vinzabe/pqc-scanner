# Security Policy

## Reporting

Report vulnerabilities responsibly to the repository owner by email to **g@abejar.net** -- do not open public issues.

## Scope

Defensive crypto-inventory tool. Use on codebases you own or are authorized to audit.

## Considerations

- The scanner reads source files and binaries but never executes them
- The LLM advisor sends finding summaries (algorithm names, file paths, counts) to the configured endpoint -- evaluate data-handling requirements
- Effort estimates are heuristics; treat them as starting points for a real migration plan, not contractual commitments
- Detectors are high-recall and may produce false positives; verify findings before scheduling work
