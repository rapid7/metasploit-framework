**Note: This documentation may need to be vetted.**

# How to send an HTTP request using Rex::Proto::Http::Client
The Rex library (Ruby Extension Library) is the most fundamental piece of the Metasploit Framework architecture. Modules normally do not interact with Rex directly, instead they depend on the framework core and its mixins for better code sharing. If you are a Metasploit module developer, the [lib/msf/core](https://github.com/rapid7/metasploit-framework/tree/master/lib/msf/core) directory should be more than enough for most of your needs. If you are writing a module that speaks HTTP, then the [[Msf::Exploit::Remote::HttpClient|./How-to-Send-an-HTTP-Request-Using-HttpClient.md]] mixin (which is found in [lib/msf/core/exploit/http/client](https://github.com/rapid7/metasploit-framework/blob/master/lib/msf/core/exploit/http/client.rb)) is most likely the one you want.

However, in some scenarios, you actually can't use the HttpClient mixin. The most common is actually when writing a form-based login module using the [[LoginScanner API|./Creating-Metasploit-Framework-LoginScanners.md]]. If you find yourself in that situation, use [Rex::Proto::Http::Client](https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb).

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
| username | String | Username for automatic authentication |
| password | String | Password for automatic authentication |

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
| uri | String | Raw URI string |
| ssl | Boolean | True to use https://, otherwise http:// |
| agent | String | User-Agent. Default is: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)|
| method | String | HTTP method |
| proto | String | Protocol |
| version | String | Version |
| vhost | String | Host header |
| port | Fixnum | Port for the host header |
| authorization | String | The authorization header |
| cookie | String | The cookie header |
| connection | String | The connection header |
| headers | Hash | A hash of custom headers. Safer than raw_headers |
| raw_headers | String | A string of raw headers |
| ctype | String | Content type |

An example of using #request_raw's options:

```ruby
# cli is a Rex::Proto::Http::Client object
req = cli.request_raw({
	'uri'    =>'/test.php',
	'method' => 'POST',
	'data'   => 'A=B'
})
```

**#request_cgi inherits all the above**, and more:

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

** request_cgi

```ruby
cli = Rex::Proto::Http::Client.new(rhost),
cli.connect
req = cli.request_cgi({'uri'=>'/'})
res = cli.send_recv(req)
cli.close
```

** request_raw

```ruby
cli = Rex::Proto::Http::Client.new(rhost),
cli.connect
req = cli.request_raw({'uri'=>'/'})
res = cli.send_recv(req)
cli.close
```

## Configuring advanced options

### Evasion Options

Rex::Proto::Http::Client also comes with its own collection of evasion options. You can set them either when you're asking Rex::Proto::Http::ClientRequest to make the HTTP request, or you can set them with a #set_config method. The main difference is that if you are using #set_config, you should make these options user-configurable.

| Option | Data type | Default | Known configurable option |
| ------ | --------- | ------- | ------------- |
| encode_params | Boolean | true | N/A |
| encode | Boolean | false | N/A |
| uri_encode_mode | String | hex-normal | HTTP::uri_encode_mode |
| uri_encode_count | Fixnum | 1 | N/A |
| uri_full_url | Boolean | false | HTTP::uri_full_url |
| pad_method_uri_count | Fixnum | 1 | HTTP::pad_method_uri_count |
| pad_uri_version_count | Fixnum | 1 | HTTP::pad_uri_version_count |
| pad_method_uri_type | String | space | HTTP::pad_method_uri_type |
| pad_uri_version_type | String | space | HTTP::pad_uri_version_type |
| method_random_valid | Boolean | false | HTTP::method_random_valid |
| method_random_invalid | Boolean | false | HTTP::method_random_invalid |
| method_random_case | Boolean | false | HTTP::method_random_case |
| version_random_valid | Boolean | false | N/A |
| version_random_invalid| Boolean | false | N/A |
| version_random_case | Boolean | false | N/A |
| uri_dir_self_reference | Boolean | false | HTTP::uri_dir_self_reference |
| uri_dir_fake_relative | Boolean | false | HTTP::uri_dir_fake_relative |
| uri_use_backslashes | Boolean | false | HTTP::uri_use_backslashes |
| pad_fake_headers | Boolean | pad_fake_headers| HTTP::pad_fake_headers |
| pad_fake_headers_count | Fixnum | 16 | HTTP::pad_fake_headers_count |
| pad_get_params | Boolean | false | HTTP::pad_get_params |
| pad_get_params_count | Boolean | 8 | HTTP::pad_get_params_count |
| pad_post_params | Boolean | false | HTTP::pad_post_params |
| pad_post_params_count | Fixnum | 8 | HTTP::pad_post_params_count |
| uri_fake_end | Boolean | false | HTTP::uri_fake_end |
| uri_fake_params_start | Boolean | false | HTTP::uri_fake_params_start |
| header_folding | Boolean | false | HTTP::header_folding |
| chunked_size | Fixnum | 0 | N/A |

### NTLM Options

HTTP authentication is automatic in Rex::Proto::Http::Client, and when it comes to the NTLM provider, it gets its own options. You MUST use the #set_config method to set them:

| Option | Data type | Default | Known configurable option |
| ------ | --------- | ------- | ------------- |
| usentlm2_session | Boolean | true | NTLM::UseNTLM2_session |
| use_ntlmv2 | Boolean | true | NTLM::UseNTLMv2 |
| send_lm | Boolean | true | NTLM::SendLM |
| send_ntlm | Boolean | true | NTLM::SendNTLM |
| SendSPN | Boolean | true | NTLM::SendSPN |
| UseLMKey | Boolean | false | NTLM::UseLMKey |
| domain | String | WORKSTATION | DOMAIN |
| DigestAuthIIS | Boolean | true | DigestAuthIIS |

Note: "Known configuration options" means there is a datastore option for it from HttpClient. If you can't use HttpClient, then you will have to consider register them yourself.

## URI Parsing

Rex::Proto::Http::Client actually does not support URI parsing, so for URI format validation and normalization, you are on your own, and you should probably do it.

For URI format validation, we recommend using Ruby's URI module. You can use HttpClient's #[target_uri](https://github.com/rapid7/metasploit-framework/blob/a65ee6cf30e6f671985876f83457cfcbea008e49/lib/msf/core/exploit/http/client.rb#L335) method as an example.

For URI normalization, we recommend HttpClient's #[normalize_uri](https://github.com/rapid7/metasploit-framework/blob/a65ee6cf30e6f671985876f83457cfcbea008e49/lib/msf/core/exploit/http/client.rb#L360) method as an example.

## Full Example

```ruby
cli = Rex::Proto::Http::Client.new(rhost, rport, {}, ssl, ssl_version, proxies, user, pass)
cli.set_config(
  'vhost' => vhost,
  'agent' => datastore['UserAgent'],
  'uri_encode_mode'        => datastore['HTTP::uri_encode_mode'],
  'uri_full_url'           => datastore['HTTP::uri_full_url'],
  'pad_method_uri_count'   => datastore['HTTP::pad_method_uri_count'],
  'pad_uri_version_count'  => datastore['HTTP::pad_uri_version_count'],
  'pad_method_uri_type'    => datastore['HTTP::pad_method_uri_type'],
  'pad_uri_version_type'   => datastore['HTTP::pad_uri_version_type'],
  'method_random_valid'    => datastore['HTTP::method_random_valid'],
  'method_random_invalid'  => datastore['HTTP::method_random_invalid'],
  'method_random_case'     => datastore['HTTP::method_random_case'],
  'uri_dir_self_reference' => datastore['HTTP::uri_dir_self_reference'],
  'uri_dir_fake_relative'  => datastore['HTTP::uri_dir_fake_relative'],
  'uri_use_backslashes'    => datastore['HTTP::uri_use_backslashes'],
  'pad_fake_headers'       => datastore['HTTP::pad_fake_headers'],
  'pad_fake_headers_count' => datastore['HTTP::pad_fake_headers_count'],
  'pad_get_params'         => datastore['HTTP::pad_get_params'],
  'pad_get_params_count'   => datastore['HTTP::pad_get_params_count'],
  'pad_post_params'        => datastore['HTTP::pad_post_params'],
  'pad_post_params_count'  => datastore['HTTP::pad_post_params_count'],
  'uri_fake_end'           => datastore['HTTP::uri_fake_end'],
  'uri_fake_params_start'  => datastore['HTTP::uri_fake_params_start'],
  'header_folding'         => datastore['HTTP::header_folding'],
  'usentlm2_session'       => datastore['NTLM::UseNTLM2_session'],
  'use_ntlmv2'             => datastore['NTLM::UseNTLMv2'],
  'send_lm'                => datastore['NTLM::SendLM'],
  'send_ntlm'              => datastore['NTLM::SendNTLM'],
  'SendSPN'                => datastore['NTLM::SendSPN'],
  'UseLMKey'               => datastore['NTLM::UseLMKey'],
  'domain'                 => datastore['DOMAIN'],
  'DigestAuthIIS'          => datastore['DigestAuthIIS']
)
cli.connect
req = cli.request_cgi({'uri'=>'/'})
res = cli.send_recv(req)
cli.close
```