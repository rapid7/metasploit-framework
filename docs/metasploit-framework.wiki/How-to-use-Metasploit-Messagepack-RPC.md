The RPC API enables you to programmatically drive the Metasploit Framework and commercial products using HTTP-based remote procedure call (RPC) services. An RPC service is a collection of message types and remote methods that provide a structured way for external applications to interact with web applications. You can use the RPC interface to locally or remotely execute Metasploit commands to perform basic tasks like running modules, communicating with the database, interacting with sessions, exporting data, and generating reports.

The Metasploit products are written primarily in Ruby, which is the easiest way to use the remote API. However, in addition to Ruby, any language with support for HTTPS and MessagePack, such as Python, Java, and C, can be used to take advantage of the RPC API.

There are currently two implementations of Metasploit's RPC:

- HTTP and messagepack - covered by this guide
- HTTP and JSON - covered by a separate guide

Note that both the messagepack and JSON RPC services provide very similar operations, and it is worth reviewing both documents.

## Starting the messagepack RPC Server

Before you can use the RPC interface, you must start the RPC server. There are a couple of ways that you can start the server depending on the Metasploit product you are using. For this example we will use the MSFRPD Login Utility, but other methods can be found [here](https://docs.rapid7.com/metasploit/rpc-api).

Use the follow command setting a username and password, current example uses `user` and `pass` retrospectively:

```
$ ruby msfrpcd -U <username> -P <pass> -f
```

## Connecting with the MSFRPC Login Utility

The msfrpc login utility enables you to connect to the RPC server through msfrpcd. If you started the server using the msfrpcd tool, `cd`  into your framework directory, if you're a Framework user, or the `metasploit/apps/pro/msf3` directory if you are a Pro user, and run the following command to connect to the server:

```
$ ruby msfrpc -U <username> -P <pass> -a <ip address>
```
You can provide the following options:

- `-P <opt>` - The password to access msfrpcd.
- `-S` - Enables or disables SSL on the RPC socket. Set this value to true or false. SSL is on by default.
- `-U <opt>` - The username to access msfrpcd.
- `-a <opt>` - The address msfrpcd runs on.
- `-p <opt>` - The port the msfrpc listens on. The default port is 55553.

For example, if you want to connect to the local server, you can enter the following command:
```
$ ruby msfrpc -U user -P pass123 -a 127.0.0.1
```

Which returns the following response:

```
[*] exec: ruby msfrpc -U user -P pass123 -a 127.0.0.1

[*] The 'rpc' object holds the RPC client interface
[*] Use rpc.call('group.command') to make RPC calls
```

## RPC Workflow examples

### Start the server

Use the following command to run the server with a configured uesrname and password:

```
$ ruby msfrpcd -U user -P pass -f
```

### Start the client in second terminal tab

Use the username and password set in the previous command to access the client:

```
# Start the client in second terminal tab
$ ruby msfrpc -U user -P pass -a 0.0.0.0
```

An interactive prompt will open:

```
[*] The 'rpc' object holds the RPC client interface
[*] Use rpc.call('group.command') to make RPC calls
```

### Commands

Before looking at commands, we will list the options that can be pass into RPC calls:
```
--rpc-host HOST
--rpc-port PORT
--rpc-ssl <true|false>
--rpc-uri URI
--rpc-user USERNAME
--rpc-pass PASSWORD
--rpc-token TOKEN
--rpc-config CONFIG-FILE
--rpc-help
```

#### Auxiliary module example

To execute the `scanner/smb/smb_enumshares` module:

```
>> rpc.call("module.execute", "auxiliary", "scanner/smb/smb_enumshares", {"RHOSTS" => "192.168.175.135", "SMBUSER" => "Administrator", "SMBPASS" => "Password1"})
=> {"job_id"=>0, "uuid"=>"yJWES2Y6d4MRyfFLWjqhqvon"}
```

Note that the result returns the `job_id` and `uuid` - which can be used for tracking the module's progress.

The arguments supplied are:

- `"module.execute"` - The method you want to call against the module
- `"auxiliary"` - the module type
- `"scanner/smb/smb_enumshares"` - The specific module you want to run
- `{"RHOSTS" => "192.168.175.135", "SMBUSER" => "Administrator", "SMBPASS" => "Password1"}` - The module's datastore options

Query all running stats with:

```
>> rpc.call('module.running_stats')
=> {"waiting"=>[], "running"=>[], "results"=>["yJWES2Y6d4MRyfFLWjqhqvon"]}
```

Note that the output contains the previous `uuid`, which has now been marked as completed.
To view the module results for a given `UUID`:

```
>> rpc.call('module.results', 'yJWES2Y6d4MRyfFLWjqhqvon')
=> {"status"=>"completed", "result"=>nil}
```

#### Listing current jobs/sessions

To list the current jobs:

```
>> rpc.call('job.list')
=> {"0"=>"Exploit: windows/smb/ms17_010_psexec"}
```

To list the current sessions:

```
>> rpc.call('session.list')
=>
{1=>
  {"type"=>"meterpreter",
   "tunnel_local"=>"192.168.8.125:4444",
   "tunnel_peer"=>"192.168.8.125:63504",
   "via_exploit"=>"exploit/windows/smb/psexec",
   "via_payload"=>"payload/windows/meterpreter/reverse_tcp",
   "desc"=>"Meterpreter",
   "info"=>"NT AUTHORITY\\SYSTEM @ DC1",
   "workspace"=>"false",
   "session_host"=>"192.168.175.135",
   "session_port"=>445,
   "target_host"=>"192.168.175.135",
   "username"=>"cgranleese",
   "uuid"=>"hqtjjwgx",
   "exploit_uuid"=>"hldyog8j",
   "routes"=>"",
   "arch"=>"x86",
   "platform"=>"windows"}}
```

#### Killing sessions

To stop an active session use the `session.stop` command and pass the session ID. To find the session ID you can use the `session.list` command. 

```
rpc.call('session.stop', 1)
```

### Example workflows

Let's look at a some workflows using the commands we discussed above for a complete workflow.

#### Auxiliary module workflow

```
[*] The 'rpc' object holds the RPC client interface 
[*] Use rpc.call('group.command') to make RPC calls

>> rpc.call("module.execute", "auxiliary", "scanner/smb/smb_enumshares", {"RHOSTS" => "xxx.xxx.xxx.xxx", "SMBUSER" => "user", "SMBPASS" => "password"})
=> {"job_id"=>0, "uuid"=>"yJWES2Y6d4MRyfFLWjqhqvon"}
>> rpc.call('module.running_stats')
=> {"waiting"=>[], "running"=>[], "results"=>["yJWES2Y6d4MRyfFLWjqhqvon"]}
>> rpc.call('module.results', 'yJWES2Y6d4MRyfFLWjqhqvon')
=> {"status"=>"completed", "result"=>nil}
```

#### Exploit module workflow

This workflow makes use of the `module.check` method to check if the target is vulnerable to the module's exploit:

```
[*] The 'rpc' object holds the RPC client interface 
[*] Use rpc.call('group.command') to make RPC calls 

>> rpc.call("module.check", "exploit", "windows/smb/ms17_010_psexec", {"RHOSTS" => xxx.xxx.xxx.xxx", "SMBUSER" => "user", "SMBPASS" => "password"}) 
=> {"job_id"=>0, "uuid"=>"q3eewYtM3LqxuVN5ai1Wya3i"} 
>> rpc.call('module.running_stats') 
=> {"waiting"=>[], "running"=>[], "results"=>["q3eewYtM3LqxuVN5ai1Wya3i"]} 
>> rpc.call('module.results', 'q3eewYtM3LqxuVN5ai1Wya3i') 
=> {"status"=>"completed", "result"=>{"code"=>"vulnerable", "message"=>"The target is vulnerable.", "reason"=>nil, "details"=>{"os"=>"Windows 8.1 9600", "arch"=>"x64"}}}
```

The `module.result` calls shows that the target is vulnerable, and additional metadata about the target has been returned.
