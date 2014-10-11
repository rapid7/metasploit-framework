The Rex library (Ruby Extension Library) is the most fundamental piece of the Metasploit Framework architecture. Modules normally do not interact with Rex directly, instead they depend on the framework core and its mixins for better code sharing. If you are a Metasploit module developer, the [lib/msf/core](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core) directory should be more than enough for most of your needs. If you are writing a module that speaks HTTP, then the [Msf::Exploit::Remote::HttpClient](https://github.com/rapid7/metasploit-framework/wiki/How-to-Send-an-HTTP-Request-Using-HTTPClient) mixin (which is found in [lib/msf/core/exploit/http/client](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/client.rb)) is most likely the one you want.

However, in some scenarios, you actually can't use the HttpClient mixin. The most common is actually when writing a form-based login module using the [LoginScanner API](https://github.com/rapid7/metasploit-framework/wiki/Creating-Metasploit-Framework-LoginScanners). If you find yourself in that situation, use [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb).

## Initializing Rex::Proto::Http::Client

The Rex::Proto::Http::Client initializer creates a new HTTP client instance, and the most important piece is this:

```ruby
def initialize(host, port = 80, context = {}, ssl = nil, ssl_version = nil, proxies = nil, username = '', password = '')
```

As you can use, only the host argument is required, the rest are optional. But let's go over all of them right quick:

| Argument name | Data type | Description |
| ------------- | --------- | ----------- |
| host | String | Target host IP |
| port | Fixnum | Target host port |
| context | Hash | Determines what is responsible for requesting that a socket can be created |
| ssl | Boolean | True to enable it |
| ssl_version | String | SSL2, SSL3, or TLS1 |
| proxies | String | Configure a proxy |
| username | Username for automatic authentication |
| password | Password for automatic authentication |

Code example of initialing Rex::Proto::Http::Client:

```ruby
cli = Rex::Proto::Http::Client.new(rhost, rport, {}, true, 8181, proxies, 'username', 'password')
```

## Making an HTTP request

Even though our main topic of this documentation is about Rex::Proto::Http::Client, it does not know how to make HTTP requests. Instead, [Rex::Proto::Http::ClientRequest](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client_request.rb) is actually the mother of all Metasploit's HTTP requests.

So how does Rex::Proto::Http::ClientRequest give birth to an HTTP request? Well, you see son, it all begins when Rex::Proto::Http::Client asks for one with either the #request_cgi or the #request_raw method. The difference is that if #request_cgi is used, the request is meant to be CGI compatible, and in most cases this is what you want. If #request_raw is used, technically it means less options, less CGI compatible.

A raw HTTP request supports the following options:

| Option/key name | Data type | Description |
| --------------- | --------- | ----------- |
| query | String | Raw GET query string |
| data | String | Raw POST data string |
| encode | Boolean | URI encoding |
| uri | String | Raw URI string |
| uri_encode_count | Fixnum | Number of times to encode |
| uri_full_url | Boolean | Full URL |
| uri_dir_fake_relative | Boolean | Enable fake relative URL |
| ssl | Boolean | True to use https://, otherwise http:// |
| agent | String | User-Agent. Default is: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)|
| method | String | HTTP method |
| method_random_valid | Boolean | A random HTTP method: GET, POST, or HEAD |
| method_random_invalid | Boolean | A random string as an HTTP method |
| method_random_case | Boolean | A random string with casings as an HTTP method |
| pad_method_uri_count | Fixnum | Number of spaces |
| pad_method_uri_type | String | Either a space, or a tab, or Apache specific |
| uri_fake_params_start | Boolean | Appends '/%3fa=b/../' |
| uri_fake_end | Boolean | Appends '/%20HTTP/1.0/../../' |
| pad_uri_version_count | Fixnum | Number of spaces between the URI and the version |
| pad_uri_version_type | String | Either a space, or a tab, or Apache specific |
| proto | String | Protocol |
| version | String | Version |
| version_random_valid | Boolean | A random version between 1.0 or 1.1 |
| version_random_invalid | Boolean | A random numeric string for the version |
| version_random_case | Boolean | A string with random casings for the version |
| vhost | String | Host header |
| port | Fixnum | Port for the host header |
| authorization | String | The authorization header |
| cookie | String | The cookie header |
| connection | String | The connection header |
| pad_fake_headers | Fixnum | Number of fake alphanumeric headers |
| headers | Hash | A hash of custom headers. Safer than raw_headers |
| raw_headers | String | A string of raw headers |
| ctype | String | Content type |
| chunked_size | Fixnum | Body chunk size. Will also set Transfer-Encoding and Content-Length to "" |

An example of using #request_raw's options:

```ruby
# cli is a Rex::Proto::Http::Client object
req = cli.request_raw({
	'uri'    =>'/test.php',
	'method' => 'POST',
	'data'   => 'A=B'
})
```

If the number of options #request_raw supports doesn't blow you mind, don't be disappointed. **#request_cgi inherits all the above**, and more:

| Option/key name | Data type | Description |
| --------------- | --------- | ----------- |
| pad_get_params | Boolean | Enable padding for GET parameters |
| pad_get_params_count | Fixnum | Number of random GET parameters. You also need pad_get_params for this |
| vars_get | Hash | A hash of GET parameters |
| encode_params | Boolean | Enable URI encoding for GET or POST parameters |
| pad_post_params | Boolean | Enable padding for POST parameters |
| pad_post_params_count | Fixnum | Number of random POST parameters. You also need pad_post_params for this |

An example of using one of #request_cgi options:

```ruby
# cli is a Rex::Proto::Http::Client object
req = cli.request_cgi({
	'uri'      =>'/test.php',
	'vars_get' => {
		'param1' => 'value',
		'param2' => 'value'
	}
})
```


## Sending an HTTP request

Here are examples of how to actually speak to an HTTP server with either #request_cgi or #request_raw:

**#request_cgi**

```ruby
cli = Rex::Proto::Http::Client.new(rhost),
cli.connect
req = cli.request_cgi({'uri'=>'/'})
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

Rex::Proto::Http::Client actually does not support URI parsing, so for URI format validation and normalization, you are on your own, and you should probably do it.

For URI format validation, we recommend using Ruby's URI module. You can use HttpClient's #[target_uri](https://github.com/rapid7/metasploit-framework/blob/a65ee6cf30e6f671985876f83457cfcbea008e49/lib/msf/core/exploit/http/client.rb#L335) method as an example.

For URI normalization, we recommend HttpClient's #[normalize_uri](https://github.com/rapid7/metasploit-framework/blob/a65ee6cf30e6f671985876f83457cfcbea008e49/lib/msf/core/exploit/http/client.rb#L360) method as an example.

## Full Example