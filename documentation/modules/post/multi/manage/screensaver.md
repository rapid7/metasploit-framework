This module allows you to control the screensaver or lock the session.

## Vulnerable Application

The following platforms are supported:


* Windows
* Linux
* OS X


**WARNING**: only Linux supports stopping the screensaver.

## Verification Steps

1. Obtain a session.
2. In msfconsole do `use post/multi/screensaver`.
3. Set the `SESSION` option.
4. Choose the action you want to perform via `set action NAME` (available actions described below).
5. Do `run`.

## Actions

**LOCK**

If you use `set action LOCK` the `run` command will lock the current session, the user will have to login again.

**START**

If you use `set action START` the `run` command will start the screensaver, depending on its settings the user may have to login again.

**STOP**

If you use `set action STOP` the `run` command will stop the screensaver.
