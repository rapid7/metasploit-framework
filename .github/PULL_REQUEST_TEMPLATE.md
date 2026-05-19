Thank you for contributing to Metasploit Framework! Your time and effort help make this project better for the entire security community. If you have questions at any point, reach out on [GitHub Discussions](https://github.com/rapid7/metasploit-framework/discussions) or the [Metasploit Slack](https://metasploit.com/slack).

<!-- For trivial changes (typo fixes, comment corrections, minor doc edits): you may delete sections that don't apply. All sections are required for code changes. -->

> **Before this PR will be reviewed, it must include:**
>
> - A clear **description** of what the change does and why
> - Specific, reproducible **verification steps**
> - **Test evidence** (console output, screenshots, or recording links)
>
> PRs that do not include these minimum requirements will be closed. Each PR should address a single module, bug fix, or cohesive logical change — focused PRs are reviewed and merged faster. PRs bundling unrelated changes will be asked to split into focused PRs before review proceeds.
>
> For full guidance, see [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md) and the [module acceptance guidelines](https://docs.metasploit.com/docs/development/maintainers/process/guidelines-for-accepting-modules-and-enhancements.html).
>
> If your PR is not yet complete, mark it as a **draft** or prefix the title with **WIP** — this signals that it is not ready for review.

### Ready for Review

- [ ] **I have read this template, completed all required sections, and my PR is ready for maintainer review.**

Leave this box unchecked if any required section is incomplete — use GitHub's draft PR feature or add a "WIP" prefix to the title instead. Committers will not begin reviewing PRs where this checkbox is unchecked, so checking it helps your contribution get reviewed sooner.

## Description

<!-- Describe what this change does. Be specific about the behavior being added or modified. -->



<!-- Explain why this change is needed. What problem does it solve or what improvement does it provide? -->



<!-- Reference any related GitHub issue(s) below (e.g., "Fixes #1234" or "Related to #5678"). Write "N/A" if no issue exists. -->

**Related Issue:** 

### Type of Change

Mark the type that best describes this PR:

- [ ] New module
- [ ] Bug fix
- [ ] Library enhancement
- [ ] Documentation
- [ ] Other (describe below)

### Breaking Changes

<!-- Does this PR change existing behavior, remove options, rename datastore settings, or alter API/mixin interfaces? If yes, describe what breaks and how users should adapt. Write "None" if not applicable. -->

None

### Reviewer Notes

<!-- (Optional) Guide the reviewer: where to start reading, what the key change is, what's intentionally left out or deferred. Delete this section if not needed. -->

> **Branch reminder:** Submit this PR from a unique topic branch to the `master` branch. Do not submit from your fork's `master` branch directly.

## Verification Steps

<!-- Provide specific, numbered steps a reviewer can follow to verify this change works as intended. Each step should reference a concrete command, UI action, or observable system behavior. Include at least one step describing the expected outcome (e.g., "Verify that a session is opened"). -->

1. - [ ] <!-- Step 1: e.g., "Start msfconsole and load the module with `use exploit/...`" -->
2. - [ ] <!-- Step 2: e.g., "Set required options: `set RHOSTS 192.0.2.1`, `set LHOST ...`" -->
3. - [ ] <!-- Step 3: e.g., "Run the module with `run` or `exploit`" -->
4. - [ ] <!-- Step 4 (expected outcome): e.g., "Verify that a Meterpreter session is opened" or "Verify the output includes the expected version string" -->

<!-- Add more steps as needed. At least one step MUST describe the expected observable outcome so the reviewer can determine pass or fail. -->

<details>
<summary>Example verification steps for common contribution types</summary>

**New module:**
1. `msfconsole`
2. `use exploit/linux/http/example_rce`
3. `set RHOSTS <target_ip>`
4. `set LHOST <attacker_ip>`
5. `check` — Verify the target is reported as vulnerable
6. `run` — Verify that a session is opened

**Library code change:**
1. `msfconsole`
2. `use auxiliary/scanner/http/example_scanner`
3. `set RHOSTS <target_ip>`
4. `run` — Verify the scanner completes without errors and outputs the expected results
5. Run the relevant RSpec tests: `bundle exec rspec spec/lib/path/to/changed_file_spec.rb` — Verify all tests pass

**Bug fix:**
1. Check out the branch prior to this fix and reproduce the bug (describe how)
2. Check out this branch
3. Repeat the reproduction steps — Verify the bug no longer occurs
4. Verify no regressions in related functionality

</details>

> **Note:** Verification steps must reference the specific module, file, or feature being changed. Generic steps such as "verify it works" or "test the module" do not help reviewers validate your contribution and will result in the PR being closed. Specific steps help reviewers validate faster, getting your work merged sooner.

## Test Evidence

<!-- Paste console output, screenshots, or links to screen recordings that demonstrate your code runs without errors and produces the expected output. Evidence must correspond to the current version of code in this PR and demonstrate the specific functionality being added or changed. -->

<!-- ⚠️ Redact sensitive information: replace real IP addresses, credentials, API keys, and hostnames with placeholders before pasting. -->

<!-- For new modules: include output from the module's `check` method (if applicable) AND successful exploitation or execution against a controlled lab/test environment target. -->

Paste your test evidence below. PRs submitted without test evidence will be closed without review — if your work is still in progress, mark the PR as a **draft** or prefix the title with **WIP** to avoid closure.

```
<!-- Replace this comment with your console output, or provide links to screenshots/recordings above the code block. -->
```

## Environment

Provide details about the environment where you tested this change. Complete environment info helps reviewers reproduce your results and speeds up the review process.

| Field | Details |
|-------|---------|
| **Operating System** | <!-- e.g., Ubuntu 22.04, Windows 11, macOS 14.2 --> |
| **Ruby Version** | <!-- e.g., 3.2.2 (run `ruby -v`) --> |
| **Target Software/Hardware** | <!-- Name and version of the software or hardware targeted by this change --> |
| **Metasploit Branch** | <!-- e.g., master --> |
| **Docker Image / Vagrant Setup** | <!-- (Optional) Image name or setup instructions if applicable, otherwise remove this row --> |

<!-- ⚠️ Incomplete environment details may delay review or result in the PR being closed until the information is provided. Help reviewers help you — fill in all applicable fields above. -->

<details>
<summary>Hardware and Complex Software Module Guidance</summary>

If your module targets specialized hardware or complex software, provide a pcap, screen recording, or video demonstration showing successful execution against the target.

**Qualifying hardware examples:**

- Switches
- Routers
- IP cameras
- IoT devices
- PLCs
- Embedded systems

**Qualifying complex software:**

- Proprietary software requiring a paid license
- Software requiring 3+ dependent services to install
- Software requiring multi-version testing across 2+ major versions

**Submitting pcaps and recordings:**

Email pcap files or recordings to [msfdev@metasploit.com](mailto:msfdev@metasploit.com). Before submitting, sanitize your pcap by removing:

- Real IP addresses
- Credentials
- Hostnames
- Any other personally identifiable information (PII)

**If hardware or software is unavailable:**

If you cannot provide a pcap or recording because the hardware or software is not available to you, state the reason in the PR description and indicate whether you can provide access or a test environment to a committer for verification.

</details>

## Pre-Submission Checklist

Verify the following before marking your PR as ready for review:

- [ ] Ran `rubocop` on changed files with no new offenses
- [ ] Ran `msftidy` on changed module files with no new offenses _(modules only)_
- [ ] Ran `msftidy_docs` on changed documentation files with no new offenses _(documentation files only)_
- [ ] Included a corresponding documentation markdown file in `documentation/modules` _(new modules only)_
- [ ] No sensitive information (IP addresses, credentials, API keys, hashes) in code or documentation
- [ ] Tested on the target environment specified in the Environment section above
- [ ] Read the [CONTRIBUTING.md](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md) guidelines

<details>
<summary>Responsiveness and PR Takeover Policy</summary>

We want every contribution to make it into the project. If approximately 2 weeks pass after a review request without a comment or code update from you, the team may take over the PR and complete the work on your behalf.

If this happens, you will remain credited as a co-author on the final commit — your contribution is always recognized.

This policy exists to keep the project moving forward. It is not a reflection on the quality of your work or your involvement. Life happens, and we would rather finish the work together than let a good contribution go stale.

</details>
