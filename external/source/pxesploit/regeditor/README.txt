
The Offline NT Password Editor

(c) 1997-2010 Petter Nordahl-Hagen

This is free software, licensed under the following:

"ntreg" (the registry library) is licensed under the GNU Lesser Public
License. See LGPL.txt.

"chntpw" (the password reset / registry editor frontend) is licensed
under the GNU General Public License, see GPL.txt.

"reged" (registry editor /export tool) is licensed
under the GNU General Public License, see GPL.txt.

See INSTALL.txt for compile/installation instructions.

Where to get more info:
-----------------------

http://pogostick.net/~pnh/ntpasswd/

At that site there's a floppy and a bootable CD that use chntpw to
access the NT/2k/XP/Vista-system it is booted on to edit password etc.
The instructions below are for the standalone program itself, not the floppy.

What does chntpw do?
--------------------

This little program will enable you to view some information and
change user passwords in a Windows NT SAM userdatabase file.
You do not need to know the old passwords.
However, you need to get at the file some way or another yourself.
In addition it contains a simple registry editor with full write support,
and hex-editor which enables you to
fiddle around with bits&bytes in the file as you wish yourself.

Why?
----

I often forget passwords. Especially on test installations (that
I just _must_ have some stuff out of half a year later..)
On most unix-based boxes you just boot the thingy off some kind
of rescue bootmedia (cd/floppy etc), and simply edit the
password file.
On Windows NT however, as far as I know, there is no way except reinstalling
the userdatabase, losing all users except admin.
(ok, some companies let you pay lotsa $$$$$ for some rescue service..)

How?
----

Currently, this thing only runs under linux, but it may just happen
to compile on other platforms, too.
(there are dos-versions available, look for links on my webpage)
So, to set a new adminpassword on your NT installation you either:
1) Take the harddrive and mount it on a linux-box
2) Use a linux-bootdisk or CD
   one is available at: http://pogostick.net/~pnh/ntpasswd/
ie. you do it offline, with the NT system down.

Usage:
------

This is usage of the "chntpw" program binary only.
For info on the bootdisk, see the web site.
Some of the output format has changed a little since the docs were
first written.

	chntpw version 0.99.2 040105, (c) Petter N Hagen
	chntpw: change password of a user in a NT SAM file, or invoke registry editor.
	chntpw [OPTIONS] <samfile> [systemfile] [securityfile] [otherreghive] [...]
	 -h          This message
	  -u <user>   Username to change, Administrator is default
	  -l          list all users in SAM file
	  -i          Interactive. List users (as -l) then ask for username to change
	  -e          Registry editor. Now with full write support!
	  -d          Enter buffer debugger instead (hex editor), 
	  -t          Trace. Show hexdump of structs/segments. (deprecated debug function)
	  -v          Be a little more verbose (for debuging)
	  -L          Write names of changed files to /tmp/changed
	  -N          No allocation mode. Only (old style) same length overwrites possible

Normal usage is:

> chntpw sam system security
  - open registry hives 'sam' and 'system' and change administrator account.
  Verions dated later from Feb 1999 and later also supports
  and will find the admin account, even if the name has been changed,
  or the name has been localized (different languageversion of NT
  use different admin-names)

The -u option:
Specifies user to change:

> chntpw -u jabbathehutt mysam
  - Prompt for password for 'jabbathehutt', if found (otherwise do nothing)
  
Or you may give RID number in hex:
> chntpw -u 0x1f4 mysam
  - Will edit administrator.

Names does not support multibyte (unicode) characters like
some russian and asian locales. Give RID in hex to edit users
with such names. Must start with 0x. Ex: 0x2fa

The -l option:
  Will list all users in the sam-file.
  
The -i option:
  Go into the interactive menu system.
  
The -d option:
  This will load the file, and then immediately enter the
  buffer debugger.
  This is a simple hex-editor with only a few commands,
  enter ? at the . prompt to se a short command overview.
  'q' exits without saving, 's' exit and saves.

The -e option:
  Will enter the registry editor.
  You can navigate the registry like a filesystem at the command-line prompt:
  See regedit.txt file for more info.

The -t option:
  This is a debug function (extended -l) to show how it traces the chain
  of structs in the file. This also includes a raw interpretation
  of the different registry structures + a hex dump.

The -L option:
  Drops the filenames of the changed hives in /tmp/changed
  Used by the bootdisk scripts.
  
The -N option:
  Will fall back to old edit mode, disable the block allocations
  and only support overwrite-same-size. Used to ensure safety
  in testing period.

How does it work:
-----------------

A struct, called the V value of a key in the NT registry
was suddenly somewhat documented through the pwdump utility
included in the unix Samba distribution.
This struct contains some info on a user of the NT machine,
along with 2 crypted versions of the password associated
with the account.

One password is the NT console login password,
the other the LANMAN network share password
(which essentially is the first one in uppercase only,
 and no unicode)

This is how NT encrypts the passwords:

The logon cleartext password a user enters is:
1) Converted to unicode
2) A MD4 hash is made out of the unicode string
3) Then the hash is crypted with DES, using the RID (lower
   part of the SID, userid) as the crypt key.
   This is the so called "obfuscation" step, so
   it's not obvious on a hex dump of the file
   that two or more users have the same password.
4) The result of stage 3 (16 bytes) is put into the V struct.

For the LANMAN password:
1) Uppercased (and illegal characters probably removed)
   14 bytes max, if less the remaining bytes are zeroed.
2) A known (constant) string is DES-encrypted
   using 7 first characters of the password as the key.
   Another constant is encrypted using the last 7 chars
   as the key.
   The result of these two crypts are simply appended,
   resulting in a 16 byte string.
3) The same obfuscation DES stage as 3 above.
4) 16 bytes result put into the V struct.

Since the number of possible combinations in the lanman
password is relatively low compared to the other one,
and it's easy to see if it's shorter than 8 chars or not
it's used first in brute-force-crackers.

This program, however, don't care at all what the old
one is, it just overwrites it with the new one.

Ok. So, how do we find and identify the V struct?
Yeah.. that was the hard part.. The files structure
is not documented (as far as I know..)

But, with help from an unnamed German, and a lot of testing
and guesswork from myself, it's now possible to follow
the actual registry tree. (see source code for struct-defines
and comments on the registry structure)

The usernames are listed in:
\SAM\Domains\Account\Users\Names\

[2d18] \SAM\Domains\Account\Users\Names> l
ls of node at offset 0x2d1c
Node has 4 subkeys and 1 values
nk-offset      name
0x003290 - <Administrator>
0x003630 - <Guest>
0x001c88 - <luser>
0x003428 - <pnh>

Each name is a subkey, with one namless value containing
the RID.

[2d18] \SAM\Domains\Account\Users\Names> cd pnh

[3428] \SAM\Domains\Account\Users\Names\pnh> l
ls of node at offset 0x342c
Node has 0 subkeys and 1 values
vk-offs    size    type           name
0x003688     0  (unknown)        <> INLINE:  val (in type field?): 1000 (0x3e8)

To get the userinfo (V struct), access
\SAM\Domains\Account\Users\<RID>\V

[2c90] \SAM\Domains\Account\Users> l
ls of node at offset 0x2c94
Node has 5 subkeys and 1 values
nk-offset      name
0x003320 - <000001F4>
0x0036b8 - <000001F5>
0x003550 - <000003E8>
0x001d00 - <000003E9>
0x002d18 - <Names>

[2c90] \SAM\Domains\Account\Users> cd 000003E8

[3550] \SAM\Domains\Account\Users\000003E8> l
ls of node at offset 0x3554
Node has 0 subkeys and 2 values
vk-offs    size    type           name
0x0035a8    80  REG_BINARY       <F>
0x003228   508  REG_BINARY       <V>

For more techincal info, look it up in the source code.
