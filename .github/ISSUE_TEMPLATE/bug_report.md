---
name: Bug Report 🐞
about: Something isn't working as expected? Here is the right place to report.
labels: "bug"
---

<!--
  Please fill out each section below, otherwise, your issue will be closed. This info allows Metasploit maintainers to diagnose (and fix!) your issue as quickly as possible.

  Useful Links:
  - Wiki: https://github.com/rapid7/metasploit-framework/wiki
  - Reporting a Bug: https://github.com/rapid7/metasploit-framework/wiki/Reporting-a-Bug

  Before opening a new issue, please search existing issues: https://github.com/rapid7/metasploit-framework/issues
-->

## Steps to reproduce

How'd you do it?

1. ...
2. ...

This section should also tell us any relevant information about the
environment; for example, if an exploit that used to work is failing,
tell us the victim operating system and service versions.

## Were you following a specific guide/tutorial or reading documentation?

If yes link the guide/tutorial or documentation you were following here, otherwise you may omit this section.

## Expected behavior

What should happen?

## Current behavior

What happens instead?

### Metasploit version

Get this with the `version` command in msfconsole (or `git log -1 --pretty=oneline` for a source install).

## Additional Information
If your version is less than `5.0.96`, please update to the latest version and ensure your issue is still present.

If the issue is encountered within `msfconsole`, please run the `debug` command using the instructions below. If the issue is encountered outisde `msfconsole`, or the issue causes `msfconsole` to crash on startup, please delete this section.

1. Start `msfconsole`
2. Run the command `set loglevel 3`
3. Take the steps necessary recreate your issue
4. Run the `debug` command
5. Copy all the output below the `===8<=== CUT AND PASTE EVERYTHING BELOW THIS LINE ===8<===` line and make sure to **REMOVE ANY SENSITIVE INFORMATION.**
6. Replace these instructions and the paragraph above with the output from step 5.
