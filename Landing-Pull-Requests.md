# Landing Pull Requests

Slightly different approaches need to be taken for landing pull requests, depending on the content and circumstances.

## Trivial Pull Requests From Known Sources

Extremely simple example from [Pull #525](https://github.com/rapid7/metasploit-framework/pull/525):

````
git checkout master
git pull -r
git fetch swtorino
git merge swtorino/edb-19322
git log
git diff origin/master
git push origin master
````

(In this case, I already have "swtorino" set up as a remote).

Comment and close on the UI that the merge happened, referencing the commit sha1 from the git log.

### Why use this strategy

The merge button in the UI compresses nearly all of this to one step, so you do lose that convenience. However, the merge button fails to track the committer of the fix -- it merges the commit directly on GitHub's side, so the SHA1 (and thus, the author), never changes.

Admittedly, this is usually not a big deal. See [Pull #489](https://github.com/rapid7/metasploit-framework/pull/489). The pull request gets the notification that wchen-r7 merged, so there is some notification. However, when looking at the change:

````
mazikeen:./metasploit-framework$ git log -1 --pretty=full 80a0b47
commit 80a0b4767a1c77dcd4092a85cc1e9d7f39be4b72
Author: Steve Tornio <swtornio@gmail.com>
Commit: Steve Tornio <swtornio@gmail.com>

    add osvdb ref
[1.9.3-p125@msf] (master) 
````

Compare that to this trivial example from #525.

````
$ git log -1 --pretty=full 5d2655b
commit 5d2655b0ce35943ec2f3403d09d07d696277c148
Author: Steve Tornio <swtornio@gmail.com>
Commit: Tod Beardsley <todb@metasploit.com>

    add osvdb ref
[1.9.3-p125@msf] (master) 
````

Clearly, Tod Beardsley is to blame for landing Steve's pull request, and it's discernible *from git's commit log itself*. Since the commit log is universally available, it's a more convenient audit trail than the pull request log (which may or may not be available in the future and more difficult to search).

The more serious problem with the merge button is that using it affords an opportunity for the pull requestor to poison the source tree out from under the committer. For small changes that can be merged quickly from trusted sources, this is not a big deal. For larger chunks of code that are neccisarily slower to review from untrusted sources, this can be dangerous. *TODO: Demo this race condition*

## Landing contained, uncomplicated modules.

Talk about landing a module here and the levels of testing expected.

## Landing core Framework code

Talk about landing framework code here, ditto on the testing, and importance of avoding rebasing.

## Resolving conflicts

Talk about preferred conflict resolution strategies (in the absence of rebasing).

## Collaboration

Talk about collaborative editing -- use the GPP module example as the wrong way to do it.
