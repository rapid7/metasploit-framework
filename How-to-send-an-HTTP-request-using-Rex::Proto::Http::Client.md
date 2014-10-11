The Rex library (Ruby Extension Library) is the most fundamental piece of the Metasploit Framework architecture. Modules normally do not interact with Rex directly, instead they depend on the framework core and its mixins for better code sharing. If you are a Metasploit module developer, the [lib/msf/core](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core) directory should be more than enough for most of your needs. If you are writing a module that speaks HTTP, then the [Msf::Exploit::Remote::HttpClient](https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient) mixin (which is found in [lib/msf/core/exploit/http/client](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/client.rb)) is most likely the one you want.

However, in some scenarios, you actually can't use the HttpClient mixin. The most common is actually when writing a form-based login module using the [LoginScanner API](https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners). If you find yourself in that situation, use [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb).

## Initializing Rex::Proto::Http::Client

## Making an HTTP request

Even though our main topic of this documentation is about Rex::Proto::Http::Client, it does not know how to make HTTP requests. Instead, [Rex::Proto::Http::ClientRequest](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client_request.rb) is actually the mother of all Metasploit's HTTP requests.

So how does Rex::Proto::Http::ClientRequest give birth to an HTTP request? Well, you see son, it all begins when Rex::Proto::Http::Client asks for one with either the #request_cgi or the #request_raw method. The difference is that if #request_cgi is used, the request is meant to be CGI compatible. If #request_raw is used, then the request is likely used to violate the HTTP specification. In most cases, you want #request_cgi.

## Sending an HTTP request

Here are examples of how to actually speak to an HTTP server with either #request_cgi or #request_raw:

**#request_cgi**

```ruby
cli = Rex::Proto::Http::Client.new(rhost),
cli.connect
req = cli.request_cgi({
	'uri'      =>'/test.php',
	'vars_get' => {
		'param1' => 'value',
		'param2' => 'value'
	},
	'vars_post' => {
		'username' => 'user',
		'password' => 'pass'
	}
})
res = cli.send_recv(req)
cli.close
```

**#request_raw**

```ruby
cli = Rex::Proto::Http::Client.new(rhost),
cli.connect
req = cli.request_raw({'uri'=>'/'})
res = cli.send_recv(req)
cli.close
```

## Configuring advanced options

## URI Parsing

## Full Example