## Goals

This module will start a keylogger on a linux target, keystrokes are then logged in a `loot` file which name is
printed when running the module.

We rely on an embedded python script for a better experience, this is acceptable since all linux distributions
now have `python` preinstalled, also the keylogger script is executed fully from memory.

> You can find the script in `external/source/linux/keylogger.py`

The keylogger uses the files in `/dev/input/event*` to read the different keystrokes, this allows it to work on
non X based desktops. The downside being that we have to manage keymaps ourselves, at the moment it will only work
on targets with a `QWERTY` keyboard.


## Verification

1. Get a mettle session on a POSIX (Linux) computer
2. `use post/linux/gather/keylogger`
3. `set SESSION <id>`
4. `run -j` **run it in the background if you want the key logger to monitor for a long time and still continue your thing**
5. You can read the loot file which is updated as new keystrokes flows in


## Options

**SESSION**

Which session to use, can be viewed via `session -l`.
