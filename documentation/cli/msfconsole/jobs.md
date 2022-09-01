Jobs
====

The `jobs` command is used to interact with modules running in the
background. Using jobs allows you to run multiple modules at once, like
multiple `exploit/multi/hander` runs with different options to listen
for different payloads to call back. Framework automatically starts
modules that wait for something to happen ("passive modules") as jobs,
and `run -j` will start any module as a job. When a module is started
as a job, you will see a message like `[*] Exploit running as
background job X.`. You will then be able to continue interacting with
Metasploit as normal, and output from the module will continue to be
printed to the console, like a background job in other shells.

Usage
-----

### Flags

#### -h

Display the help banner.

#### -i JOB_ID

Show details of the specified `JOB_ID`, including the name and the time
the job was started.

#### -K

Stop all currently running jobs.

#### -k JOB_IDS

Stop the specified list of jobs. See [msfconsole > Building ranges and
lists](../msfconsole.md#building-ranges-and-lists) for more details on
how to build ranges.

#### -l

List all the currently running jobs. This is the default action. Module
name, payload, and some payload configuration is shown when present.

#### -P

Save each of the currently running jobs to be restarted when
`msfconsole` is started. Only valid for jobs running payload handlers.
See [Persistence](#persistence) below.

#### -p JOB_IDS

Save the specified list of jobs to restarted when `msfconsole` is
started. Only valid for jobs running payload handlers. See
[Persistence](#persistence) below and [msfconsole > Building ranges and
lists](../msfconsole.md#building-ranges-and-listss) for how to specify
a list of `JOB_IDS`.

#### -S FILTER

Apply a search filter for the output. Currently ignored.

#### -v

Show verbose information with `-i` and `-l`. When combined with `-i`,
display the advanced options given to the module run. When combined
with `-l` or no other flags, displays an expanded table of jobs, adding
the URI for HTTP payload handlers, start time, handler options (if
present), and whether the job has been persisted with `-p` or `-P`.

Persistence
-----------

The `-P` and `-p JOB_IDS` flags save payload handler jobs to be started
every time `msfconsole` is started. This works by saving the
information needed to start an equivalent `exploit/multi/handler` run
as a JSON blob in the job persistence file, `~/.msf4/persist` by
default.

Examples
--------

Starting a module as a job:

    msf5 exploit(multi/handler) > run -j
    [*] Exploit running as background job 1.

A verbose listing of all the jobs:

    msf5 exploit(multi/handler) > jobs -v
    
    Jobs
    ====
    
      Id  Name                    Payload                          Payload opts          URIPATH  Start Time                 Handler opts  Persist
      --  ----                    -------                          ------------          -------  ----------                 ------------  -------
      1   Exploit: multi/handler  windows/meterpreter/reverse_tcp  tcp://127.0.0.1:4444           2019-02-20 19:02:58 -0600                true

Set some jobs to be started on `msfconsole` start:

    msf5 exploit(multi/handler) > jobs -p 1-2
    Added persistence to job 1.
    Added persistence to job 2.

Getting information about a specific job:

    msf5 exploit(multi/handler) > jobs -i 1
    
    Name: Generic Payload Handler, started at 2019-02-20 19:03:19 -0600
    msf5 exploit(multi/handler) > jobs -i 1 -v
    
    Name: Generic Payload Handler, started at 2019-02-20 19:03:19 -0600
    
    Module advanced options:
    
       Name                    Current Setting  Required  Description
       ----                    ---------------  --------  -----------
       ContextInformationFile                   no        The information file that contains context information
       DisablePayloadHandler   false            no        Disable the handler code for the selected payload
       EnableContextEncoding   false            no        Use transient context when encoding payloads
       ExitOnSession           true             yes       Return from the exploit after a session has been created
       ListenerTimeout         0                no        The maximum number of seconds to wait for new sessions
       VERBOSE                 false            no        Enable detailed status messages
       WORKSPACE                                no        Specify the workspace for this module
       WfsDelay                0                no        Additional delay when waiting for a session
