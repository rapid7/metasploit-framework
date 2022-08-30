# Creating Your First PR - An Intro To Git and the PR Process
## Intro
Congratulations fellow traveler, so you're interested in contributing to Metasploit eh? Well welcome aboard, its going to be a fun ride!
You'll learn lots along the way but here are some tips and tricks that should help you get started with making your first PR request
whilst also avoiding some common pitfalls and learning how some of our systems work.

## Initial Steps and Important Notes
The rest of this guide assumes you have already followed the steps at [Setting Up A Developer Environment](https://r-7.co/MSF-DEV) in order to get
a fork of Metasploit set up and ready to run, and that you have added in your SSH keys 
(see [Adding a New SSH Key To Your GitHub Account](https://docs.github.com/en/authentication/connecting-to-github-with-ssh/adding-a-new-ssh-key-to-your-github-account)), 
set up Ruby and optionally the PostgreSQL database, and done any custom shortcuts you wish to configure.

## Getting the Latest Version of Metasploit Framework
Before making any new contributions, you will want to sure you are running the latest version of Metasploit Framework.
To do this run `git checkout master && git fetch upstream && git pull`, where `upstream` is the branch connected to the 
Rapid7 remote, aka Rapid7's copy of the code. You can verify that `upstream` is set correctly by running `git remote get-url upstream`
and verifying it is set to `git@github.com:rapid7/metasploit-framework.git`.

Once you run this command, it will check out the `master` branch, then fetch all
the changes from `upstream` (which should be configured to be Rapid7's copy of Metasploit Framework on GitHub). Once
it has cached these changes, the `git pull` command will then pull these changes into the current branch, aka `master`.

Not pulling down changes before writing new code could lead to big issues down the line, particularly if someone has edited a file
you intended to modify. In that case maintainers will then have to try find the right combination of changes to implement, which could lead
to your PR being rejected if these changes are too complex.

## Making Sure Your Gems Are Updated
The next step is to make sure you have the latest copy of the Gems that Metasploit Framework depends on. This can be done by running `bundle install`
from the same directory as where the `Gemfile.lock` file is located, which will be in the same folder as wherever you cloned your fork to locally.

Doing this will allow you to make sure that you are running the latest libraries, which will ensure if you do encounter any bugs whilst
developing code, those bugs are not related to out of date Gems being installed, and are therefore potentially legitimate bugs that need fixing.

## Creating a New Branch for Your Code
Once all of this is done, you will want to create a new branch for your code, which can be done by running `git checkout -b <your branch name here>`.
This will snapshot the current branch that you are on, and use that to create a new branch with the name provided. Note that I did say snapshot. This is
why it's important to update the current branch's code to the latest version of Metasploit Framework available prior to running this command,
otherwise the new branch will contain outdated code.

## Adding in Your Changes and Creating Meaningful Commit Messages
Once you have made your code changes, add them using `git add <path to file to add> <optional path to second file to add>`. Note that you can
specify multiple files to add using `git add` at the same time.

To commit these changes locally, use `git commit -m "<commit message here>"`. Note that as a general rule of thumb, commit messages should aim
to be 50 characters or less while telling readers what was changed in that commit. You generally don't want to create commits that do multiple things at once,
instead create a separate commit for each group of items that you are changing, and make sure that the commit message reflects what changed in a general sense.

Note also that maintainers may end up squashing your commits down so that your commit A, B, and C, now become commit D which
contains all of the same changes as commit A, B, and C, but in one commit and with one associated commit message. This is often
done when the code is ready to be landed into Metasploit Framework to help make the commit history easier for people to read.

## Checking for Code Errors
Before code can be accepted into Metasploit Framework, it must also pass our RuboCop and MsfTidy rules. These help ensure that
all contributors are committing code that follows a common set of standards. To check if your code meets our RuboCop standards, 
from the root of wherever you cloned your fork of Metasploit Framework to on disk, run `rubocop <path to your module from current directory>`.

Specifying the `-a` parameter will ask RuboCop to check your module and if possible fix any issues that RuboCop is able to fix.
In this case the command would be `rubocop -a <path to your module from current directory>`. It is encouraged to keep running 
this command and fixing any issues that come up until RuboCop no longer comes back with any errors to report. Once this is 
complete, run `git add <file>` followed by `git commit -m "RuboCop Fixes"`. You can change the commit message if you 
want, but it should mention RuboCop as it helps maintainers know what the commit is related to.

As a good practice rule, you should always separate your commits that contain RuboCop changes from those that contain non-RuboCop related changes.
This helps ensure that when it comes time to review your code, review can proceed a lot quicker and more efficiently.

Note that special cases exist if you are writing library code as our RuboCop rules are primarily designed to be run against modules.
If at any point you are confused r.e this, please feel free to reach out and ask us for help on Slack at https://metasploit.com/slack.

Once this is done, the next tool to run is located in the root of the Metasploit local fork at `tools/dev/msftidy.rb`. You will want to run this tool
against your module code (if applicable), using `tools/dev/msftidy.rb <path to module>`. This will give some output if there are any errors, or no output
if your module passed the tests. Try and fix any errors mentioned here.

## Writing Documentation
The next step to do, if you are writing a module, is to write the documentation for the module. You can find some information 
on how to write module documentation at [Writing Module Documentation](https://docs.metasploit.com/docs/development/quality/writing-module-documentation.html).

In general when writing documentation you will want to search for a similar documentation file under the `documentation`
folder located in the root of the Metasploit fork. You can then copy one of these files and use it as the basis for writing
your new documentation for your module.

When writing the information for the documentation, be sure to make sure your installation steps are as clear as possible. Any confusion over
how to set up the target to be exploited will likely result in delays. You will want to put as much detail here as possible.

Additionally any information about caveats, scenarios you have tested, custom options you added in, or quirks you noticed
should also go into this file.

## Checking Documentation Syntax
Once you have written the documentation, you then want to run `toos/dev/msftidy_docs.rb <path to documentation file>`. This will report on any
errors with your documentation file, which you will want to fix before submitting your PR. Notice however that if you get a warning about long lines,
these may be okay to ignore depending on the context. A good example is if a line is long merely because of a URL. Such warnings can be
safely ignored.

## Submitting Your Changes and Opening a PR
Once you have gone through all of the steps above you should be ready to submit your PR. To submit your PR, first check which 
branch points to your copy of the code. If you have followed the setup guide, it should be `origin`. You can double check this 
branch's remote URL using `git remote get-url origin`. It should look something like `git@github.com:gwillcox-r7/metasploit-framework`
with `gwillcox-r7` substituted for your username.

Assuming the `origin` branch is in fact pointing to your copy of the code, run `git push origin local-branch:remote-branch` 
and replace `local-branch` with the branch locally where your code changes are located, and `remote-branch` with what 
you want this branch to be called on the remote repository, aka `origin` which will be your fork on GitHub.com. In most 
cases you will want these two names to be the same to avoid confusion, but its good to know this syntax should you 
start working with more complex situations. Note that if the branch pointing to your copy of the code is not named `origin`,
replace the word `origin` in the command above with the name of the branch that does point to your copy of the code.

This should result in output similar to the following:

```
> git push origin update_mssql_lib_parameters:update_mssql_lib_parameters
Enumerating objects: 15, done.
Counting objects: 100% (15/15), done.
Delta compression using up to 2 threads
Compressing objects: 100% (8/8), done.
Writing objects: 100% (8/8), 1.55 KiB | 1.55 MiB/s, done.
Total 8 (delta 7), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (7/7), completed with 7 local objects.
remote: 
remote: Create a pull request for 'update_mssql_lib_parameters' on GitHub by visiting:
remote:      https://github.com/gwillcox-r7/metasploit-framework/pull/new/update_mssql_lib_parameters
remote: 
To github.com:gwillcox-r7/metasploit-framework
 * [new branch]            update_mssql_lib_parameters -> update_mssql_lib_parameters
```

To create a new pull request (aka PR), browse to the URL mentioned in this output. In this case for the output above this would
be `https://github.com/gwillcox-r7/metasploit-framework/pull/new/update_mssql_lib_parameters`.

This will open a new template to create a PR request. Please follow all of the directions here and provide the requested details whilst also
deleting the template text once you have provided the requested information. Note that PRs that do not provide anything but the template text for
their description will be closed.

In your PR description you should take care to mention what it is that you are submitting, details on the type of vulnerability and CVE-ID,
if applicable, how to test the submission, as well as any special concerns or items of note that occurred whilst conducting testing.

Once this is done a member of our team will review your PR within a few days and provide feedback on any changes that may still need to be made
before the submission can be accepted.
