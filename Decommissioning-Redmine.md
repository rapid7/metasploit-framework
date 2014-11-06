# Decommissioning Redmine
Thanks to the recent upgrades to [GitHub Issues][gh-issues], Rapid7 is decommissioning our [Redmine instance][redmine] as an issue tracker. This means that bug reports and feature requests can begin and end in GitHub for our open source projects -- notably, the Metasploit Framework and Meterpreter.

But, never fear! The Redmine data isn't going anywhere any time soon. This will be a phased shutdown to allow for the opportunity to move old bugs to the new(ish) issue trackers. The Redmine data covers several years of Metasploit development, and may still be useful for future Metasploit historians, so we will be sure to hang on to it.

The process of converting will be largely manual. While APIs exist for converting Redmine bugs and features to GitHub issues, we're looking at merely several dozen bugs to survive as active issues. If you're curious, you can take a look at the 46 surviving [Metasploit bugs][msf-bugs] and 8 [Meterpreter bugs][meterpreter-bugs]; they're all tagged with the "GitHub" boolean (which is available to Metasploit contributors)

## What will convert
All old bugs from pre-4.8.0 are assumed to be non-active issues. Metasploit 4.8.0 was two releases ago, and was finished in November of 2013. If a bug has been around for two releases and 10 months, it's unlikely to be that huge of a show-stopper.

If you'd like to check out some old bugs and decide that they're really worth working on, you are invited to check the [Cutoff Query][cutoff] and pick and choose out of there. Please be conservative; many, many of these bugs are really wishlist items, have long been fixed or worked around in successive releases, or are unimportant enough to ignore for a long, long time.

If you have committer rights to Metasploit, just checkbox it as "GitHub" and we (or you!) will take care of it. If you don't have committer rights, please recreate the issue on GitHub Issues (and mention the Redmine link in the description, if you would like to reference it).

If new bugs show up between now and the shutdown, that's okay; we'll just handle them on a case-by-case (either resolve it on the spot or convert it over and note on the bug where the new issue is).

In all cases, when bugs are recreated on GitHub, please link to the issue URL in the original bug, otherwise it'll be easy to accidentally dupe bugs.

## Example converted bug
Check out bug [8776](https://dev.metasploit.com/redmine/issues/8776#note-4) and the corresponding issue on GitHub, [3766](https://github.com/rapid7/metasploit-framework/issues/3766). Note that each issue references the other in the comments, so that's handy.

## Shutdown Sequence
Here's how and when we plan to shut down Redmine

| Date | Action | Complete? |
|--------|----------|---------------|
|   Sep 3, 2014  |  Triage bugs younger than 4.8.0    |   Yes          |
|   Sep 5, 2014  |  Announce the change   |  Yes, [here][blog-redmine]          |
|   Sep 8, 2014  | Document process | Yes! |
|   Sep 9, 2014 | Update Project descriptions to point at GitHub | Yes|
|   Sep 9, 2014 | Update CONTRIBUTING.md | PR [#3776](https://github.com/rapid7/metasploit-framework/pull/3776)  |
|   Sep 10, 2014 | Start converting bugs | Yes! [See the list](https://dev.metasploit.com/redmine/issues?per_page=100&query_id=741) |
|  Sep 24, 2014 | Lock Redmine against new issues from non-Contributors. | Yes |
|  Oct 7, 2014 | Reset all users passwords prior to export | No |
|  Oct 10, 2014 | Complete the conversion to GitHub Issues | Yes! [See the list](https://dev.metasploit.com/redmine/issues?per_page=100&query_id=741) |
|  Dec 13, 2014 | Export the Redmine database and offer as a tarball download | No |
|  Dec 13, 2014 | Update Project descriptions to list the tarball download | No |
|  Jan 5, 2015 | Deactivate Redmine, tweet and blog about it. | No |

**Update**: Turns out, sanitizing the Redmine instance for mass distribution is kind of hard -- we're not really anxious about accidentally shipping sensistive info that was access controlled by the UI. I don't believe that the last three steps here will be trivial to accomplish, so bumping out the dates for now.

It's possible that Redmine will just cease to be, which will be sad, but I haven't heard anyone really outside of Rapid7 wanting to maintain the historical data.

----

[gh-issues]: https://github.com/blog/1866-the-new-github-issues
[redmine]: https://dev.metasploit.com/redmine
[msf-bugs]: https://dev.metasploit.com/redmine/projects/framework/issues?query_id=741
[meterpreter-bugs]: https://dev.metasploit.com/redmine/projects/meterpreter/issues?query_id=741
[blog-redmine]: https://community.rapid7.com/community/metasploit/blog/2014/09/05/weekly-metasploit-update
[cutoff]: https://dev.metasploit.com/redmine/issues?query_id=739
