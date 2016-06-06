Release notes inform our users about the stuff we're shipping in each release. By looking at our release notes, our users should be able to easily understand what's new, what's fixed, and what's changed in the release. Therefore, **all PRs, except for minor fixes and tweaks, must have release notes.**

## Writing the Release Notes 

A release note summarizes the pull request and describes the value of the fix/feature to the user. Each release note has a title, a PR number, and a brief description. 

Here's an example of what a release note looks likes:

>**Capture keystrokes, screenshots, and webcam snapshots with Beholder (PR-6878)** - The Beholder plugin automatically captures keystrokes, screenshots, and webcam snapshots from your active sessions. Run this plugin to collect data from your compromised targets every 30 seconds. 

### Writing Release Notes for an Enhancement

An enhancement indicates that an improvement or new feature has been added to the framework. Enhancements include things like auxiliary modules, post-exploitation modules, and new payloads. 

When you write release notes for an enhancement, you should try to answer the following questions:

* What is the enhancement?
* Why is it valuable or important to users?
* How can they use it?

For example, the following is a release note for an enhancement:

> **Resolve command for Meterpreter (PR-6802)** - The new  'resolve' command enables you to perform DNS lookups with Meterpreter, without leaving the session to run additional modules. To resolve host names on the target, you can run the 'resolve' command followed by the host name. For example, in the Meterpreter prompt, you can type something like 'resolve rapid7.com' to view the host resolutions for rapid7.

### Writing Release Notes for a Defect

A defect is a fix for an issue that caused a particular feature or functionality to not work the way it's expected to work. Basically, a defect indicates that something was broken, and we've fixed it. 

When you write release notes for a defect, you should try to answer the following questions:

* What was broken?
* How was it fixed?
* Why is this important to users? 

Here's an example for a defect: 

> **AWS SES rejected email from Metasploit (PR-6854)** - The email header contained duplicate date and subject headers, which caused email servers like AWS SES, to reject the emails. This fix removes the duplicate headers so that emails can be sent successfully.

### Writing Release Notes for an Exploit

An exploit is a module that takes advantage of a vulnerability and provides some type of access to the target. We call out exploits explicitly because they're the hotness.

When you write release notes for an exploit, you should try to answer the following questions:

* What vulnerability is the module exploiting?
* What type of access can you achieve with the module?
* Do you need credentials to exploit the vulnerability?

And finally, here's an example for exploits:

>HP Data Protector 6.10/6.11/6.20 Install Service - This module allows you to exploit HP Data Protector, a backup and recovery system, to remotely upload files to the file share. Versions 6.10, 6.10, and 6.20 are vulnerable. Authentication is not required to exploit this vulnerability.

## Adding Release Notes to a Pull Request

To add a release note to a pull request, you'll need to add it as a comment, like so:

![](http://i1097.photobucket.com/albums/g350/doanosaur/release-notes-comment_zpsaxt2dznn.png)

You'll need to tag the comment for inclusion in the release notes by using the `# Release Notes` heading. After you apply the release notes heading, you can enter the release notes text you want to use. 

That's it! After you add the release notes text, we'll be able to extract them from the pull requests when we run our release notes script and compile them into a single document. 

## Setting Up Your Environment

In order to run the release notes script, you'll need to do the following:

* Add the MSFDIR environment variable to your bash profile
* Install the following gems: git, oktokit, nokogiri, and redcarpet. 

### Adding the MSFDIR Variable to Your Bash Profile

To add the MSFDIR variable to your bash profile:

1. Go to /path/to/bash/profile. On OSX, it's ~/.bash_profile. On Linux, it's /home/<your username>/.bash_profile. 
1. Add the following line to the file: `export MSFDIR="/Users/wchen/rapid7/msf"`.
1. Save the file. 

### Installing the Required Gems

You'll need to install the following gems in order to run the release notes script successfully: git, octokit, nokogiri, and redcarpet. 

To install the gems, run the following:

```
$ gem install git
$ gem install octokit
$ gem install nokogiri
$ gem install redcarpet
```

## Downloading the Release Notes Script

You'll need the release notes script if you want to be able to run it. To download it, go to //fs2/xchg/shared_resources/get_release_notes.rb. 

You can store this script wherever you want. 

## Generating the Release Notes for MSF PRs

Before you can run the release notes script, you'll need to know the framework tags you want to use. You can either specify a range of framework tags, such as 4.11.0-4.12.5, or a single framework tag. If you specify a range, you'll see all the pull requests landed for those tags. If you specify a framework tag, the script finds all the PRs from that tag until the most recent tag. 

1. Cd into your framework directory.
1. Pull the latest from master. 
1. Run the following: ruby get_release_notes.rb <replace with framework tag>. 

The console displays all of the PRs for the framework tags specified. The script also extracts the content and saves it into a file called release_notes_[starting tag]_[end tag].html in the same directory as the script.

And that's it! That's how you can generate release notes from pull requests. 