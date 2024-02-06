Maintainers can assign labels to both issues and pull requests.

### Attic

When we move something to the attic it means that what you submitted is a thing that we want but the circumstances were not quite right for landing it. Sometimes this is on us, and sometimes the contribution needs more work. We recognize that contributors work on the PRs they submit at their own pace. Take a look at the comments and review suggestions on your PR, and feel free to re-open it if and when you have time to work on it again. Don't think you'll be able to get it across the finish line? Find a community champion to do it for you.

### Bug

Any PR that fixes a bug or an issue that raises awareness of a bug in the framework.

### Breaking Change

Features that are great, but will cause breaking changes and should be deployed on a large release.

### Code Quality

When a PR improves code quality.

### Confirmed

Specifically for issues that have been confirmed by a committer.

### Docs

Documentation changes, such as YARD markup, or README.md, or something along those lines.

### External Modules

PRs dealing with modules run as their own process.

### Heartbleed

Has to do with heartbleed. This will go away soon, but there are three outstanding still...

### Hotness

Something we're really excited about.

### Library

Touches something in /lib.

### Meterpreter

Has to do with Meterpreter, or depends on a Meterpreter change to land to work.

### Misc

Plugins and scripts, anything that's not otherwise defined.

### Module

Touches something in /modules.

### Needs Linting

The module needs additional work to pass our automated linting rules.

### Needs More Information

The issue lacks enough detail to replicate/resolve successfully.

### Newbie Friendly

Something that's pretty easy to test or tackle.

### Needs unique branch

Your submitted a PR from your `master` branch.

Because of how GitHub tracks changes between branches and what got added in a particular PR, we don't accept contributions from the `master` branch of your fork. All branches are [required to be unique](https://github.com/rapid7/metasploit-framework/blob/master/CONTRIBUTING.md#code-contributions). If your PR is closed because of this, create a new branch with that code and we'll be happy to look at it again!
```
git checkout -b <BRANCH_NAME>
git push <your_fork_remote> <BRANCH_NAME>
```
This helps protect the process, ensure users are aware of commits on the branch being considered for merge, allows for a location for more commits to be offered without mingling with other contributor changes and allows contributors to make progress while a PR is still being reviewed.

### Needs-docs

When a module is uploaded without a corresponding documentation file, add this label in indicate docs are required

### Not Stale

Label to stop an issue from being auto closed.

### Osx

Label for any osx related work.

### Payload

Touches something related to a payload.

### RN (Release notes)

There are a series of labels that are added to all PRs when they are landed that define the release notes for the PR.
They are denoted by the `rn-` prefix and they are important as they are used by automation to track metasploit-framework
statistics:

#### rn-enhancement

Release notes for an enhancement.

#### rn-fix

Release notes for a fix.

#### rn-modules

Release notes for new or majorly enhanced modules.

#### rn-no-release-notes

The PR is too small or insignificant to warrant release notes.

#### rn-wiki

Release notes for Metasploit Framework wiki.

### Stale

Marks an issue as stale, to be closed if no action is taken.

### Suggestion

Suggestions for new functionality.

### Suggestion-docs

New documentation suggestions.

### Suggestion-feature

New feature suggestions.

### Suggestion-Module

New module suggestions.

### Usability

Usability improvements.

### YARD

YARD Documentation Tasks for API Documentation.
