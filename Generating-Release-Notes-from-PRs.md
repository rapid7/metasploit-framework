Release notes inform our users about the stuff we're shipping in each release. By looking at our release notes, our users should be able to easily understand what's new, what's fixed, and what's changed in the release. Therefore, all PRs, except for minor fixes and tweaks, must have release notes. 

## Writing Release Notes for a Pull Request

A release note summarizes the pull request and describes the value of the fix/feature to the user. Each release note has a title, a PR number, and a brief description. 

For example, the following is a release note for an enhancement:

```
**Resolve command for Meterpreter (PR-6802)** - The new  'resolve' command enables you to perform DNS lookups with Meterpreter, without leaving the session to run additional modules. To resolve host names on the target, you can run the 'resolve' command followed by the host name. For example, in the Meterpreter prompt, you can type something like 'resolve rapid7.com' to view the host resolutions for rapid7.
```

Here's another example for a defect: 

```
AWS SES rejected email from Metasploit (PR-6854) - The email header contained duplicate date and subject headers, which caused email servers like AWS SES, to reject the emails. This fix removes the duplicate headers so that emails can be sent successfully.
```

And finally, here's an example for exploits:

```
HP Data Protector 6.10/6.11/6.20 Install Service - This module allows you to exploit HP Data Protector, a backup and recovery system, to remotely upload files to the file share. Versions 6.10, 6.10, and 6.20 are vulnerable. Authentication is not required to exploit this vulnerability.
```

## Generating the Release Notes for MSF PRs