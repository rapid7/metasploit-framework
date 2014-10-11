The Rex library (Ruby Extension Library) is the most fundamental piece of the Metasploit Framework architecture. Modules normally do not interact with Rex directly, instead they depend on the framework core and its mixins for better code sharing. If you are a Metasploit module developer, the [lib/msf/core](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core) directory should be more than enough for most of your needs. If you are writing a module that speaks HTTP, then the [Msf::Exploit::Remote::HttpClient](https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient) mixin (which is found in [lib/msf/core/exploit/http/client](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/client.rb)) is most likely the one you want.

However, in some scenarios, you actually can't use the HttpClient mixin. The most common is actually when writing a form-based login module using the [LoginScanner API](https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners). If you find yourself in that situation, use [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb).

## Initializing Rex::Proto::Http::Client

## Making an HTTP request

Even though our main topic of this documentation is about Rex::Proto::Http::Client, it does not know how to make HTTP requests. Instead, [Rex::Proto::Http::ClientRequest](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client_request.rb) is actually the mother of all Metasploit's HTTP requests.

So how does Rex::Proto::Http::ClientRequest give birth to an HTTP request? Well, you see son, it all begins when Rex::Proto::Http::Client asks for one with either the #request_cgi or the #request_raw method. The difference is that if #request_cgi is used, the request is meant to be CGI compatible, and in most cases this is what you want. If #request_raw is used, technically it means less options, less CGI compatible.

A raw HTTP request supports the following options:

| Option/key name | Description |
| --------------- | ----------- |
| query | Raw GET query string |
| data | Raw POST data string |
| encode | URI encoding |
| uri | Raw URI string |
| uri_encode_count | Number of times to encode |
| uri_full_url | Full URL |
| uri_dir_fake_relative | A fake relative URL |
| ssl | True to use https://, otherwise http:// |
| agent | User-Agent. Default is: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)|
| method | HTTP method |
| method_random_valid | A random HTTP method: GET, POST, or HEAD |
| method_random_invalid | A random string as an HTTP method |
| method_random_case | A random string with casings as an HTTP method |
| pad_method_uri_count | Number of spaces |
| pad_method_uri_type | Either a space, or a tab, or Apache specific |
| uri_fake_params_start | Appends '/%3fa=b/../' |
| uri_fake_end | Appends '/%20HTTP/1.0/../../' |
| pad_uri_version_count | Number of spaces between the URI and the version |
| pad_uri_version_type | Either a space, or a tab, or Apache specific |
| proto | Protocol |
| version | Version |
| version_random_valid | A random version between 1.0 or 1.1 |
| version_random_invalid | A random numeric string for the version |
| version_random_case | A string with random casings for the version |
| vhost | Host header |
| port | Port for the host header |
| authorization | The authorization header |
| cookie | The cookie header |
| connection | The connection header |
| pad_fake_headers | Number of fake alphanumeric headers |
| headers | A hash of custom headers. Safer than raw_headers |
| raw_headers | A string of raw headers |
| ctype | Content type |
| chunked_size | Body chunk size. Will also set Transfer-Encoding and Content-Length to "" |


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