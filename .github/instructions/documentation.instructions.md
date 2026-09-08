---
applyTo: "documentation/**/*.md"
---

# Module Documentation Instructions

## Template

Follow `documentation/modules/module_doc_template.md` for structure.

## Required Sections

1. **Introduction** — what the module does, what vulnerability it exploits
2. **Vulnerable Application** — affected versions, fixed version, setup instructions
3. **Verification Steps** — numbered steps to reproduce/verify
4. **Scenarios** — must be filled out by a human with real console output

## Rules

- Run `ruby tools/dev/msftidy_docs.rb <file>` before submitting
- Module descriptions should only use ASCII characters
- Include the range of vulnerable versions and the fixed version when known
- Do NOT include sensitive information (real IPs, credentials, API keys)
- Local/private IPs are acceptable in scenario examples
