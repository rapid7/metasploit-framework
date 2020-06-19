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

You might also want to check the last ~1k lines of
`/opt/metasploit/apps/pro/engine/config/logs/framework.log` or
`~/.msf4/logs/framework.log` for relevant stack traces


## System stuff

### Metasploit version

Get this with the `version` command in msfconsole (or `git log -1 --pretty=oneline` for a source install).

### I installed Metasploit with:
- [ ] Kali package via apt
- [ ] Omnibus installer (nightly)
- [ ] Commercial/Community installer (from http://www.rapid7.com/products/metasploit/download.jsp)
- [ ] Source install (please specify ruby version)

### OS

What OS are you running Metasploit on?

