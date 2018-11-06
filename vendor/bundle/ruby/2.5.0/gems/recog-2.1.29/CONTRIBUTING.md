# Contributing to Recog

The users and maintainers of Recog would greatly appreciate any contributions
you can make to the project.  These contributions typically come in the form of
filed bugs/issues or pull requests (PRs).  These contributions routinely result
in new versions of the [recog gem](https://rubygems.org/gems/recog) to be
released.  The process for everything is described below.

## Contributing Issues / Bug Reports

If you encounter any bugs or problems with Recog, please file them
[here](https://github.com/rapid7/recog/issues/new), providing as much detail as
possible.  If the bug is straight-forward enough and you understand the fix for
the bug well enough, you may take the simpler, less-paperwork route and simply
fill a PR with the fix and the necessary details.

## Contributing Code

Recog uses a model nearly identical to that of
[Metasploit](https://github.com/rapid7/metasploit-framework) as outlined
[here](https://github.com/rapid7/metasploit-framework/wiki/Setting-Up-a-Metasploit-Development-Environment),
at least from a ```git``` perspective.  If you've been through that process
(or, even better, you've been through it many times with many people), you can
do exactly what you did for Metasploit but with Recog and ignore the rest of
this document.

On the other hand, if you haven't, read on!

### Fork and Clone

Generally, this should only need to be done once, or if you need to start over.

1. Fork Recog: Visit https://github.com/rapid7/recog and click Fork,
   selecting your github account if prompted
2.  Clone ```git@github.com:<your-github-username>/recog.git```, replacing
```<your-github-username>``` with, you guessed it, your Github username.
3.  Add the master Recog repository as your upstream:

 ```
   git remote add upstream git://github.com/rapid7/recog.git
 ```
4. Update your `.git/config` to ensure that the `remote ["upstream"]` section is configured to pull both branches and PRs from upstream.  It should look something like the following, in particular the second `fetch` option:

    ```
     [remote "upstream"]
      url = git@github.com:rapid7/recog.git
      fetch = +refs/heads/*:refs/remotes/upstream/*
      fetch = +refs/pull/*/head:refs/remotes/upstream/pr/*
     ```
5. Fetch the latest revisions, including PRs:

    ```
    git fetch --all
    ```

### Branch and Improve

If you have a contribution to make, first create a branch to contain your
work.  The name is yours to choose, however generally it should roughly
describe what you are doing.  In this example, and from here on out, the
branch will be FOO, but you should obviously change this:

```
git fetch --all
git checkout master
git rebase upstream/master
git checkout -b FOO
```

Now, make your changes, commit as necessary with useful commit messages.

Please note that changes to [lib/recog/version.rb](https://github.com/rapid7/recog/blob/master/lib/recog/version.rb) in PRs are almost never necessary.

Now push your changes to your fork:

```
git push origin FOO
```

Finally, submit the PR.  Navigate to ```https://github.com/<your-github-username>/recog/compare/FOO```, fill in the details and submit.

### Testing

When your PR is submitted, it will be automatically subjected to the full run of tests in [Travis](https://travis-ci.org/rapid7/recog/), however you are encourage to perform testing _before_ submitting the PR.  To do this, simply run `rake tests`.

## Updating CPEs

There exists some automation to update the CPEs that might be asserted with
some recog fingerprints.  This should be run periodically to ensure that all
fingerprints that could have CPEs do, etc.

First, setup a python3 venv:

  ```
  python3 -m venv venv
  source venv/bin/activate
  pip install -r requirements.txt
  ```

Download the latest CPE 2.3 dictionary:

  ```
  wget https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz
  ````

Run the CPE automation against every XML file, using GNU `parallel` to speed things up:

  ```
  ls xml/*.xml | parallel --gnu "./update_cpes.py {} official-cpe-dictionary_v2.3.xml cpe-remap.yaml && xmllint --format --noblanks {} > {}.bak &&  mv {}.bak {} || echo {}" 2> errors.txt
  ```

Any mismatched fingerprints will be listed in `errors.txt` for eventual
maintenance.  The `cpe-remap.yaml` file can be used to map between
vendor/product/etc differences between Recog and CPE, or to work around bugs in
either.

## Landing PRs

(Note: this portion is a work-in-progress.  Please update it as things change)

Much like with the process of submitting PRs, Recog's process for landing PRs
is very similar to [Metasploit's process for landing
PRs](https://github.com/rapid7/metasploit-framework/wiki/Landing-Pull-Requests).
In short:

1. Follow the "Fork and Clone" steps from above
2. Update your `.git/config` to ensure that the `remote ["upstream"]` section is configured to pull both branches and PRs from upstream.  It should look something like the following, in particular the second `fetch` option:

    ```
     [remote "upstream"]
      url = git@github.com:rapid7/recog.git
      fetch = +refs/heads/*:refs/remotes/upstream/*
      fetch = +refs/pull/*/head:refs/remotes/upstream/pr/*
     ```
3. Fetch the latest revisions, including PRs:

    ```
    git fetch --all
    ```
4. Checkout and branch the PR for testing.  Replace ```PR``` below with the actual PR # in question:

    ```
    git checkout -b landing-PR upstream/pr/PR
    ```
5. Test the PR (see the Testing section above)
6. Merge with master, re-test, validate and push:

    ```
    git checkout -b upstream-master --track upstream/master
    git merge -S --no-ff --edit landing-PR # merge the PR into upstream-master
    # re-test if/as necessary
    git push upstream upstream-master:master --dry-run # confirm you are pushing what you expect
    git push upstream upstream-master:master # push upstream-master to upstream:master
    ```
7. If applicable, release a new version (see next section)

## Releasing New Versions

When Recog's critical parts are modified, for example its fingerprints or underlying supporting code, a new version _must_ eventually be released.  These new releases can then be optionally included in projects such as Metasploit or products such as Rapid7's Nexpose in a controlled manner.  Releases for non-functional updates such as updates to documentation are not necessary.

When a new version of Recog is to be released, you _must_ follow the instructions below.

1. If are not already a Recog project contributor for the Recog gem (you'd be listed [here under OWNERS](https://rubygems.org/gems/recog)), become one:
  1. Get an account on [Rubygems](https://rubygems.org)
  2. Contact one of the Recog project contributors (listed [here under OWNERS](https://rubygems.org/gems/recog) and have them add you to the Recog gem.  They'll need to run:
    ```
      gem owner recog -a EMAIL
    ```
2. Edit [lib/recog/version.rb](https://github.com/rapid7/recog/blob/master/lib/recog/version.rb) and increment ```VERSION```.  Commit and push to rapid7/recog master.
3. Run `rake release`.  Among other things, this creates the new gem, uploads it to Rubygems and tags the release with a tag like `v<VERSION>`, where `<VERSION>` is replaced with the version from `version.rb`.  For example, if you release version 1.2.3 of the gem, the tag will be `v1.2.3`.
4. If your default remote repository is not `rapid7/recog`, you must ensure that the tags created in the previous step are also pushed to the right location(s).  For example, if `origin` is your fork of recog and `upstream` is `rapid7/master`, you should run `git push --tags --dry-run upstream` to confirm what tags will be pushed and then `git push --tags upstream` to push the tags.
