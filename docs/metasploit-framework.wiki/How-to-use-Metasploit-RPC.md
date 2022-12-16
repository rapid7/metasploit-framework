# RPC API
The RPC API enables you to programmatically drive the Metasploit Framework and commercial products using HTTP-based remote procedure call (RPC) services. An RPC service is a collection of message types and remote methods that provide a structured way for external applications to interact with web applications. You can use the RPC interface to locally or remotely execute Metasploit commands to perform basic tasks like running modules, communicating with the database, interacting with sessions, exporting data, and generating reports.

The Metasploit products are written primarily in Ruby, which is the easiest way to use the remote API. However, in addition to Ruby, any language with support for HTTPS and MessagePack, such as Python, Java, and C, can be used to take advantage of the RPC API.

# Starting the RPC Server
Before you can use the RPC interface, you must start the RPC server. There are a couple of ways that you can start the server depending on the Metasploit product you are using. For this example we will use the MSFRPC Login Utility, but other methods can be found [here](https://docs.rapid7.com/metasploit/rpc-api).

## Connecting with the MSFRPC Login Utility

The msfrpc login utility enables you to connect to the RPC server through msfrpcd. If you started the server using the msfrpcd tool,  `cd`  into your framework directory, if you're a Framework user, or the  `metasploit/apps/pro/msf3`  directory if you are a Pro user, and run the following command to connect to the server:
```
$ ruby msfrpc -U <username>  -P <pass>  -a <ip address>
```
You can provide the following options:

-   `-P <opt>`  - The password to access msfrpcd.
-   `-S`  - Enables or disables SSL on the RPC socket. Set this value to true or false. SSL is on by default.
-   `-U <opt>`  - The username to access msfrpcd.
-   `-a <opt>`  - The address msfrpcd runs on.
-   `-p <opt>`  - The port the msfrpc listens on. The default port is 55553.

For example, if you want to connect to the local server, you can enter the following command:
```
$ ruby msfrpc -U user -P pass123 -a 0.0.0.0
```
Which returns the following response:
```
[*] exec: ruby msfrpc -U user -P pass123 -a 0.0.0.0

[*] The 'rpc' object holds the RPC client interface
[*] Use rpc.call('group.command') to make RPC calls
```

# RPC Workflow examples
## Getting the server and client set up
### Start the server in first terminal tab
Use the follow command setting a username and password, current example uses `user` and `pass` retrospectively:
```
$ ruby msfrpcd -U user -P pass -f
```

### Start the client in second terminal tab
Then use the username and password set in the previous command to access the client:
```
# Start the client in second terminal tab
$ ruby msfrpc -U user -P pass -a 0.0.0.0
```
Once your client is up and running you will see the following output:
```
[*] The 'rpc' object holds the RPC client interface
[*] Use rpc.call('group.command') to make RPC calls
```

## Commands
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

### Auxiliary module example
This example uses the `scanner/smb/smb_enumshares` module. The following commarnd is used to get a module running via RPC, this command passes all the information the module needs to execute:
```
>> rpc.call("module.execute", "auxiliary", "scanner/smb/smb_enumshares", {"RHOSTS" => "192.168.175.135", "SMBUSER" => "Administrator", "SMBPASS" => "Password1"})
=> {"job_id"=>0, "uuid"=>"yJWES2Y6d4MRyfFLWjqhqvon"}
```
The output of the above command returns the `job_id` and `uuid` which are used to reference the running module via commands we will discuss later.

Below we will breakdown each argument:

| Argument  | Explanation  |
|---|---|
|  "module.execute" | The method you want to call against the module |
| "auxiliary" | The module type |
| "scanner/smb/smb_enumshares" | The specific module you want to run |
| {"RHOSTS" => "192.168.175.135", "SMBUSER" => "Administrator", "SMBPASS" => "Password1"} | The options you want to pass to the module |

Let's look at some commands that can be used once we have a module running. First we have `running_stats`, this will return the current state of the module:
```
>> rpc.call('module.running_stats')
=> {"waiting"=>[], "running"=>[], "results"=>["yJWES2Y6d4MRyfFLWjqhqvon"]}
``` 
The above output makes use of the `uuid` of our current module and returns the results with the `uuid` present in whichever state the module is currently in. In the above example our module has completed and is in the results state. If we wanted to view that modules results we would use the following command:
```
>> rpc.call('module.results', 'yJWES2Y6d4MRyfFLWjqhqvon')
=> {"status"=>"completed", "result"=>nil}
```
Here we pass the running modules `uuid` into the `module.results` command and it returns that our module status is marked as completed.

### Listing current jobs/sessions
To list the current jobs use the following command:
```
>> rpc.call('job.list')
=> {"0"=>"Exploit: windows/smb/ms17_010_psexec"}
```

To list the current sessions use the following command:
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

### Killing sessions
To stop an active session use the `session.stop` command and pass the session ID. To find the session ID you can use the sessions list command in the above section:
```
rpc.call('session.stop', 1)
```

## Example workflows
Let's look at a some workflows using the commands we discussed above for a complete workflow.

### Auxiliary module workflow
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

### Exploit module workflow
This workflow makes use of the `module.check` method to check if a module is vulnerable to the exploit that is passed:
```
[*] The 'rpc' object holds the RPC client interface 
[*] Use rpc.call('group.command') to make RPC calls 

>> rpc.call("module.check", "exploit", "windows/smb/ms17_010_psexec", {"RHOSTS" => xxx.xxx.xxx.xxx", "SMBUSER" => "user", "SMBPASS" => "password"}) 
=> {"job_id"=>0, "uuid"=>"q3eewYtM3LqxuVN5ai1Wya3i"} 
>> rpc.call('module.running_stats') 
=> {"waiting"=>[], "running"=>[], "results"=>["q3eewYtM3LqxuVN5ai1Wya3i"]} 
>> rpc.call('module.results', 'q3eewYtM3LqxuVN5ai1Wya3i') 
=> {"status"=>"completed", "result"=>{"code"=>"vulnerable", "message"=>"The target is vulnerable.", "reason"=>nil, "details"=>{"os"=>"Windows 8.1 9600", "arch"=>"x64"}}} >>
```
As we can see above the check method returns more data on the running module stating it's vulnerable and returning some information the target machine.
