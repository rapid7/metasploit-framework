Sometimes, modules contributed to Metasploit don't quite cross the finish line. This can be for a variety of reasons. Most often, it is because the module submission was a "drive-by" -- the original author is not interested (or not able) to implement and test needed changes in order to make the module production worthy.

Luckily, git makes it easy to be a pack rat for these unfinished modules. We have a separate branch for these unstable modules, imaginatively named, [Unstable](https://github.com/rapid7/metasploit-framework/tree/unstable).

## Landing to Unstable

Unstable modules have their own special directory structure -- they should **not** hit the regular `modules/` subdirectory, since we don't want to conflict with existing or future modules. We also want to make it easy to spot which modules are unstable. So, new modules should get landed there with the following procedure.

1. Create a local branch off of the PR: `git checkout -b temp-pr1234 --track upstream/pr/1234`
1. Create a local branch off of unstable: `git checkout -b unstable-pr1234-modulename --track upstream/unstable`
1. Find the module paths: `git diff upstream/master...upstream/pr/1234`
1. Git checkout the module(s) in question: `git checkout temp-pr1234 modules/exploits/path/to/module.rb`
1. Move the files to the appropriate directory: `git mv modules/exploits/path/to/module.rb unstable-modules/exploits/incomplete`
1. Commit the result: `git commit`
1. Send a pull request targeting the unstable branch, **not** the master branch: https://github.com/YOU/metasploit-framework/compare/rapid7:unstable...unstable-pr1234-modulename?expand=1 . Be sure to mention the original pull request number in the description so the PR will be updated accordingly.

This assumes you're set up for development a la http://r-7.co/MSF-DEV with Rapid7's branch being the "upstream" repo. 

## Example

For an example of this procedure, see [PR #2801](https://github.com/rapid7/metasploit-framework/pull/2801).

## Unstable Libraries

If someone has library changes that cannot be merged to master, we cannot hang on to them in unstable. There is no sensible way to maintain that kind of branch over any reasonable time period, since conflicts will surely abound soon. Unstable scripts and plugins are okay, though.

## Rescuing unstable modules

If you'd like to rescue an unstable module, great! Just note that it's an unstable rescue in the pull request, and the original PR number (if you can find it), when you pull it back out. You can do a similiar `git checkout` to grab the file and then `git mv` it to the right spot again.

## Safety

This is not `unstable` in the Debian sense -- they're not latest versions, they get no fixes unless someone adopts them, and they may end up crashing out all of framework when loaded. No guarantees are made, ever, despite things like `ExploitRanking.`