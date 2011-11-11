====================
PRELUDE:
====================
    The original implementation was ca. 2004 by Ryan Lim as an academic
    project.  It was later picked up and maintained at bindshell.net, adding
    fixes for the JtR 1.7 releases and various cipher patches.

    In 2008, it was picked up by AoZ and stripped back down to the original
    MPI-only changes to improve its compatibility with the 'jumbo' patchsets,
    which had better-maintained alternate cipher support. This is often
    referred to as "the mpi10 patch"

    In 2010, it was extended by magnum to support all cracking modes. This
    should be referred to as "the fullmpi patch" to avoid confusion. With the
    exception of Markov it is far from perfect but it works just fine and
    should support correct resuming in all modes. It is well tested but you
    have absolutely NO guarantees.

====================
COMPILING:
====================
    Unless using OMP, you should consider applying the nsk-3 patch, also known
    as "Faster bitslice DES key setup".

    To enable MPI in John, un-comment these two line in Makefile:

----8<--------------8<--------------8<--------------8<--------------8<----------
# Uncomment the TWO lines below for MPI (can be used together with OMP as well)
CC = mpicc -DHAVE_MPI
MPIOBJ = john-mpi.o
----8<--------------8<--------------8<--------------8<--------------8<----------

    You must have an operational MPI environment prior to both compiling and
    using the MPI version; configuring one is outside the scope of this
    document but for a single, multi-core, host you don't need much
    configuration. MPICH2 or OpenMPI seems to do the job fine, for example.
    Most testing of fullmpi is now done under latest stable OpenMPI.

    Debian Linux example for installing OpenMPI:
    sudo apt-get install libopenmpi-dev openmpi-bin

    Note that this patch works just fine together with OMP enabled as well.
    When MPI is in use (with more than one process), OMP is (by default)
    automatically disabled. Advanced users may want to change this setting
    (change MPIOMPmutex to N in john.conf) and start one MPI node per
    multi-core host, letting OMP do the rest. Warnings are printed; these
    can be muted in john.conf too.

====================
USAGE:
====================
    Typical invocation is as follows:

    mpiexec -np 4 ./john --incremental passwd

    The above will launch four parallel processes that will split the
    Incremental keyspace in a more-or-less even fashion. If you run it to
    completion, some nodes will however finish very early due to how this
    mode is implemented, decreasing the overall performance. This problem
    gets much worse with a lot of nodes.

    In MARKOV mode, the range is automatically split evenly across the nodes,
    just like you could do manually. This does not introduce any overhead,
    assuming job runs to completion - and also assuming your MPI compiler
    behaves.

    The single and wordlist modes scale fairly well and cleartexts will not be
    tried by more than one node (except when different word + rule combinations
    result in the same candidate, but that problem is not MPI specific).

    In SINGLE mode, and sometimes in Wordlist mode (see below), john will
    distribute (actually leapfrog) the rules (after preprocessor expansion).
    This works very well but will not likely result in a perfectly even
    workload across nodes.

    WORDLIST mode with rules will work the same way. Without rules, or when
    rules can't be split across the nodes, john will distribute (again, it
    really just leapfrogs) the words instead. This is practically the same as
    using the External:Parallel example filter in john.conf, but much more user
    friendly.

    If the --mem-file-size parameter (default 5000000) will allow the file to
    be loaded in memory, this will be preferred and each node will only load
    its own share of words. In this case, there is no further leapfrogging and
    no other overhead. Note that the limit is per node, so using the default
    and four nodes, a 16 MB file WILL be loaded to memory, with 4 MB on each
    node.

    You can override the leapfrogging selection. This is debug code really and
    should eventually be replace by proper options:

       --mem-file-size=0   (force split loading, no leapfrog)
       --mem-file-size=1   (force leapfrogging of words)
       --mem-file-size=2   (force leapfrogging of rules)

    In EXTERNAL mode, john will distribute candidates in the same way as in
    Wordlist mode without rules. That is, all candidates will be produced on
    all nodes, and then skipped by all nodes but one. This is the mode where
    the fullmpi patch performs worst. When attacking very fast formats, this
    scales VERY poorly.


    You may send a USR1 signal to the parent MPI process (or HUP to all
    individual processes) to cause the subprocesses to print out their status.
    Be aware that they may not appear in order, because they blindly share the
    same terminal.

    skill -USR1 -c mpiexec

    Another approach would be to do a normal status print. This must be done
    with mpiexec and using the same -np as used for starting the job:

    mpiexec -np 4 ./john --status

    Which will dump the status of each process as recorded in the .rec files.
    This way you also get a line with total statistics.

====================
CAVEATS:
====================
    - This implementation does not account for heterogeneous clusters or nodes
      that come and go.
    - In interest of cooperating with other patches, benchmarking is less
      accurate.  Specifically, it assumes all participant cores are the same
      as the fastest.
    - Benchmark virtual c/s will appear inflated if launching more processes
      than cores available. It will basically indicate what the speed would be
      with that many real cores.
    - There is no inter-process communication of cracked hashes yet. This means
      that if one node cracks a hash, all other nodes will continue to waste
      time on it. The current workaround is aborting and restarting the jobs
      regularly. This also means that you may have to manually stop some or all
      nodes after all hashes are cracked.
    - Aborting a job using ctrl-c will often kill all nodes without updating
      state files and logs. I have tried to mitigate this but it is still a
      good idea to send a -USR1 to the parent before killing them. You should
      lower the SAVE parameter in john.conf to 60 (seconds) if running MPI,
      this will be the maximum time of repeated work after restarting.

============================================================
Following is the verbatim original content of this file:
============================================================

This distribution of John the Ripper (1.6.36) requires MPI to compile.

If you don't have MPI, download and install it before proceeeding.

Any bugs, patches, comments or love letters should be sent to
jtr-mpi@hash.ryanlim.com. Hate mail, death threates should be sent to
/dev/null.

Enjoy.
--
Ryan Lim <jtr-mpi@hash.ryanlim.com>
