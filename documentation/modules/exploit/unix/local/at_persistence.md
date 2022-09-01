## Vulnerable Application

This module executes a metasploit payload utilizing `at(1)` to execute jobs at a specific time.  It should work out of the box
with any UNIX-like operating system with `atd` running.  In the case of OS X, the `atrun` service must be launched:

```
sudo launchctl load -w /System/Library/LaunchDaemons/com.apple.atrun.plist
```

## Verification Steps

  1. Start msfconsole
  2. Exploit a box via whatever method
  3. Do: `use exploit/unix/local/at_persistence`
  4. Do: `set session #`
  5. Do: `set target #`
  6. `exploit`


## Options

  **TIME**

  When to run job via at(1).  Changing may require WfsDelay to be adjusted.

  **PATH**

  Path to store payload to be executed by at(1).  Leave unset to use mktemp.

## Scenarios

This module is useful for running one-shot payloads with delayed execution. It is slightly less obvious than cron.
