Release notes inform our users about the stuff we're shipping in each release. By looking at our release notes, our users should be able to easily understand what's new, what's fixed, and what's changed in the release. Therefore, **all PRs, except for minor fixes and tweaks, must have release notes.**

To add a release note to a pull request, you'll need to add it as a comment, like so:

![Release Notes Example](https://i.imgur.com/dgzQxyD.png)

You'll need to tag the comment for inclusion in the release notes by using the `# Release Notes` heading. After you apply the release notes heading, you can enter the release notes text you want to use. 

That's it! After you add the release notes text, we'll be able to extract them from the pull requests when we run our release notes script and compile them into a single document. 

## Writing Release Notes 

Okay, so now that you know how to add a release note, you're wondering what you're supposed to write. 

Basically, a release note summarizes the pull request and describes the value of the fix/feature to the user. Each release note has a title, a PR number, and a brief description. 

Here's an example of what a release note looks likes:

>The Beholder plugin automatically captures keystrokes, screenshots, and webcam snapshots from your active sessions. Run this plugin to collect data from your compromised targets every 30 seconds. 

## Types of Release Notes

There are three types of release notes:
* [Enhancement](#release-notes-for-enhancements)
* [Fix](#release-notes-for-fixes)
* [Modules](#release-notes-for-modules)

### Release Notes for Enhancements

An enhancement indicates that an improvement or new feature has been added to the framework. Enhancements include things like auxiliary modules, post-exploitation modules, and new payloads. 

When you write release notes for an enhancement, you should try to answer the following questions:

* What is the enhancement?
* Why is it valuable or important to users?
* How can they use it?

For example, the following is a release note for an enhancement:

> The new  'resolve' command enables you to perform DNS lookups with Meterpreter, without leaving the session to run additional modules. To resolve host names on the target, you can run the 'resolve' command followed by the host name. For example, in the Meterpreter prompt, you can type something like 'resolve rapid7.com' to view the host resolutions for Rapid7.

### Release Notes for Fixes

A fix is for an issue that caused a particular feature or functionality to not work the way it's expected to work. Basically, a defect indicates that something was broken, and we've fixed it. 

When you write release notes for a fix, you should try to answer the following questions:

* What was broken?
* How was it fixed?
* Why is this important to users? 

Here's an example for a fix: 

> The email header contained duplicate date and subject headers, which caused email servers like AWS SES, to reject the emails. This fix removes the duplicate headers so that campaigns can send emails successfully. 

### Release Notes for Modules

An exploit is a module that takes advantage of a vulnerability and provides some type of access to the target. We call out exploits explicitly because they're the hotness.

When you write release notes for an exploit, you should try to answer the following questions:

* What vulnerability is the module exploiting?
* What type of access can you achieve with the module?
* Do you need credentials to exploit the vulnerability?

And finally, here's an example for exploits:

> This module allows you to exploit HP Data Protector, a backup and recovery system, to remotely upload files to the file share. Versions 6.10, 6.10, and 6.20 are vulnerable. You don’t need to authenticate to exploit this vulnerability. 

