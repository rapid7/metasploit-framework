Repeat
======

The `repeat` command repeats one or more console commands for a fixed number of
times, a certain length of time, or forever. The repeat command is most useful
for repeating module runs like memory dumpers or scanners that have a random
element to them.

Usage
-----

### Flags

#### -t, --time SECONDS

Start the list of commands until the number of seconds has elapsed.

#### -n, --number TIMES

Start the list of commands a fixed number of times.

#### -h, --help

Display the help banner.



Examples
--------

Run the heartbleed module every 10 seconds against a server for an hour:

    msf5 > use auxiliary/scanner/ssl/openssl_heartbleed
    msf5 auxiliary(scanner/ssl/openssl_heartbleed) > set ACTION DUMP
    # Set other options...
    msf5 auxiliary(scanner/ssl/openssl_heartbleed) > repeat -t 3600 run; sleep 10

