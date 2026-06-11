Thank you for contributing to Metasploit Framework! Your time and effort help make this project better for the entire security community. If you have questions at any point, reach out on [GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions) or the [Metasploit Slack](https://metasploit.com/slack).

<!-- For trivial changes (typo fixes, comment corrections, minor doc edits): you may delete sections that don't apply. -->

<!-- PRs missing a description, verification steps, or test evidence will be closed. Each PR should address a single module, bug fix, or cohesive logical change. For full guidance, see CONTRIBUTING.md and the module acceptance guidelines linked below. If your PR is not yet complete, mark it as a draft or prefix the title with WIP. -->

## Description

<!-- Describe what this change does. Be specific about the behavior being added or modified. -->



<!-- Explain why this change is needed. What problem does it solve or what improvement does it provide? -->



<!-- Reference any related GitHub issue(s) below (e.g., "Fixes #1234" or "Related to #5678"). Delete this line if not applicable. -->

**Related Issue:** 

## Breaking Changes

<!-- Does this PR change existing behavior, remove options, rename datastore settings, or alter API/mixin interfaces? If yes, describe what breaks and how users should adapt. Write "None" if not applicable. -->

None

## Reviewer Notes

<!-- (Optional) Guide the reviewer: where to start reading, what the key change is, what's intentionally left out or deferred. Delete this section if not needed. -->

## Verification Steps

<!-- Provide specific, numbered steps a reviewer can follow to verify this change works as intended. At least one step must describe the expected observable outcome. Generic steps such as "verify it works" will result in the PR being closed. -->

1. - [ ] 



## Test Evidence

<!-- Paste console output, screenshots, or links to screen recordings. Redact sensitive information. -->

<!-- For new modules: include output from the module's `check` method (if applicable) AND successful exploitation or execution against a controlled lab/test environment target. -->

## Environment

| Field | Details |
|-------|---------|
| **Operating System** | <!-- e.g., Ubuntu 22.04, Windows 11, macOS 14.2 --> |
| **Ruby Version** | <!-- e.g., 3.2.2 (run `ruby -v`) --> |
| **Target Software/Hardware** | <!-- Name and version of the software or hardware targeted by this change --> |
| **Docker Image / Vagrant Setup** | <!-- (Optional) Image name or setup instructions if applicable, otherwise remove this row --> |

## AI Usage Disclosure

<!-- Was AI used in the creation of this PR? If so, describe what tools were used and how (e.g., code generation, documentation drafting, test writing). Write "None" if no AI tools were used. -->



## Pre-Submission Checklist

- [ ] Ran [`rubocop`](https://docs.metasploit.com/docs/development/quality/using-rubocop.html) on new files with no new offenses _(net new files only)_
- [ ] Ran [`msftidy`](https://docs.metasploit.com/docs/development/quality/msftidy.html) on changed module files with no new offenses _(modules only)_
- [ ] Ran [`msftidy_docs`](https://docs.metasploit.com/docs/development/quality/writing-module-documentation.html#before-you-submit-your-pr-msftidy_docsrb) on changed documentation files with no new offenses _(documentation files only)_
- [ ] Included a corresponding documentation markdown file in `documentation/modules` _(new modules only)_
- [ ] No sensitive information (IP addresses, credentials, API keys, hashes) in code or documentation
- [ ] Tested on the target environment specified in the Environment section above
- [ ] Included RSpec tests for library changes _(encouraged for `lib/` changes)_
- [ ] Read the [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md) and [module acceptance guidelines](https://docs.metasploit.com/docs/development/maintainers/process/guidelines-for-accepting-modules-and-enhancements.html)

<details>
<summary>Hardware and Complex Software Module Guidance</summary>

If your module targets specialized hardware (routers, IoT, PLCs, etc.) or complex software (licensed, multi-service, or multi-version), provide a pcap, screen recording, or video showing successful execution.

Email sanitized pcaps/recordings to [msfdev@metasploit.com](mailto:msfdev@metasploit.com) — remove real IPs, credentials, and hostnames before sending. If hardware/software is unavailable, explain in the PR description.

</details>

<details>
<summary>Responsiveness and PR Takeover Policy</summary>

We want every contribution to make it into the project. If approximately 2 weeks pass after a review request without a comment or code update from you, the team may take over the PR and complete the work on your behalf.

If this happens, you will remain credited as a co-author on the final commit — your contribution is always recognized.

This policy exists to keep the project moving forward. It is not a reflection on the quality of your work or your involvement. Life happens, and we would rather finish the work together than let a good contribution go stale.

</details>
