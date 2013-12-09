Using multiple networking mixins in a Metasploit module is always a tricky thing to do, because most likely you will run into issues like overlapping datastore options, variables, methods, the super call is only meant for one mixin, etc. This is considered as advanced module development, but sometimes can be rather painful to figure out on your own. To improve the Metasploit development experience, we have a few examples to demonstrate common scenarios that require you to use multiple mixins to achieve exploitation. 

### Today's lesson: Send a HTTP request to attack the target machine, and use a HttpServer for payload delivery.

Say you want to exploit a web server or web application. You have code execution on the box, but you need to find a way to deliver the final payload (probably an executable), and a HTTP server happens to be your option.

Here is how you can set it up:

```ruby

##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Remote::HttpServer::HTML

  def initialize(info={})
    super(update_info(info,
      'Name'           => "HttpClient and HttpServer Example",
      'Description'    => %q{
        This demonstrates how to use two mixins (HttpClient and HttpServer) at the same time,
        but this allows the HttpServer to terminate after a delay.
      },
      'License'        => MSF_LICENSE,
      'Author'         => [ 'sinn3r' ],
      'References'     =>
        [
          ['URL', 'http://metasploit.com']
        ],
      'Payload'        => { 'BadChars' => "\x00" },
      'Platform'       => 'win',
      'Targets'        =>
        [
          [ 'Automatic', {} ],
        ],
      'Privileged'     => false,
      'DisclosureDate' => "Dec 09 2013",
      'DefaultTarget'  => 0))

      register_options(
        [
          OptString.new('TARGETURI', [true, 'The path to some web application', '/']),
          OptInt.new('HTTPDELAY',    [false, 'Number of seconds the web server will wait before termination', 10])
        ], self.class)
  end

  def on_request_uri(cli, req)
    print_status("#{peer} - Payload request received: #{req.uri}")
    send_response(cli, 'You get this, I own you')
  end

  def primer
    print_status("Sending a malicious request to #{target_uri.path}")
    send_request_cgi({'uri'=>normalize_uri(target_uri.path)})
  end

  def exploit
    begin
      Timeout.timeout(datastore['HTTPDELAY']) { super }
    rescue Timeout::Error
      # When the server stops due to our timeout, this is raised
    end
  end
end
```

Here's what happens when you run the above example:

1. The super call wrapped in the Timeout block will start the web server.
2. Before the web server is in the infinite loop state, the primer() method is called, which is where you send your malicious requests to get code execution.
3. Your HttpServer serves the final payload upon request.
4. After 10 seconds, the module raises a Timeout exception. The web server finally terminates.

In case you're wondering why the web server must terminate after a period of time, this is because if the module fails to gain code execution on the target machine, obviously it will never ask your web server for the malicious payload, therefore there is no point to keeping it alive forever. Typically it shouldn't take a very long time to get a payload request, either, so we keep the timeout short.

The output for the above example should look something like this:

```
msf exploit(test) > run
[*] Exploit running as background job.

[*] Started reverse handler on 10.0.1.76:4444 
[*] Using URL: http://0.0.0.0:8080/SUuv1qjZbCibL80
[*]  Local IP: http://10.0.1.76:8080/SUuv1qjZbCibL80
[*] Server started.
[*] Sending a malicious request to /
msf exploit(test) >
[*] 10.0.1.76        test - 10.0.1.76:8181 - Payload request received: /SUuv1qjZbCibL80
[*] Server stopped.

msf exploit(test) >
```

### Related Articles:

* https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient
* https://github.com/rapid7/metasploit-framework/wiki/How-to-write-a-browser-exploit-using-HttpServer
* https://community.rapid7.com/community/metasploit/blog/2012/12/17/metasploit-hooks