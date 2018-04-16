This is an example of how to write a module that uses the [HttpClient](https://rapid7.github.io/metasploit-framework/api/Msf/Exploit/Remote/HttpClient.html) mixin to send a basic HTTP request.

### There are mainly two common methods you will see:

* **[send_request_raw](https://rapid7.github.io/metasploit-framework/api/Msf/Exploit/Remote/HttpClient.html#send_request_raw-instance_method)** - You use this to send a raw HTTP request. Usually, you will want this method if you need something that violates the specification; in most other cases, you should prefer `send_request_cgi`.  If you wish to learn about how this method works, look at the documentation for [`Rex::Proto::Http::Client#request_raw`](https://rapid7.github.io/metasploit-framework/api/Rex/Proto/Http/Client.html#request_raw-instance_method).
 
Here's a basic example of how to use `send_request_raw`:

```ruby
	send_request_raw({'uri'=>'/index.php'})
```

* **[send_request_cgi](https://rapid7.github.io/metasploit-framework/api/Msf/Exploit/Remote/HttpClient.html#send_request_cgi-instance_method)** - You use this to send a more CGI-compatible HTTP request. If your request contains a query string (or POST data), then you should use this.  If you wish to learn about how this method works, check out [`Rex::Proto::Http::Client#request_cgi`](https://rapid7.github.io/metasploit-framework/api/Rex/Proto/Http/Client.html#request_cgi-instance_method).

Here's a very basic example for `send_request_cgi`:

```ruby
	send_request_cgi({
		'method'   => 'GET',
		'uri'      => '/hello_world.php',
		'vars_get' => {
			'param_1' => 'abc',
			'param_2' => '123'
		}
	})
```

**Please note**: `send_request_raw` and `send_request_cgi` will return a `nil` if there's a timeout, so please make sure to account for that condition when you handle the return value.

### URI Parsing

Before you send a HTTP request, you will most likely have to do some URI parsing.  This is a tricky task, because sometimes when you join paths, you may accidentally get double slashes, like this: "/test//index.php".  Or for some reason you have a missing slash.  These are really commonly made mistakes.  So here's how you can handle it safely:

**1** - Register your default URI datastore option as 'TARGETURI':

Example:

```ruby
	register_options(
		[
			OptString.new('TARGETURI', [true, 'The base path to XXX application', '/xxx_v1/'])
		], self.class)
```

**2** - Load your TARGETURI with [`target_uri`](https://rapid7.github.io/metasploit-framework/api/Msf/Exploit/Remote/HttpClient.html#target_uri-instance_method), that way the URI input validation will kick in, and then you get a real `URI` object:

In this example, we'll just load the path:

```ruby
	uri = target_uri.path
```

**3** - When you want to join another URI, always use [`normalize_uri`](https://rapid7.github.io/metasploit-framework/api/Msf/Exploit/Remote/HttpClient.html#normalize_uri-instance_method):

Example:

```ruby
	# Returns: "/xxx_v1/admin/upload.php"
	uri = normalize_uri(uri, 'admin', 'upload.php')
```

**4** - When you're done normalizing the URI, you're ready to use `send_request_cgi` or `send_request_raw`

Please note: The `normalize_uri` method will always follow these rules:

1. The URI should always begin with a slash.
2. You will have to decide if you need the trailing slash or not.
3. There should be no double slashes.

### Full Example

```ruby

	require 'msf/core'

	class MetasploitModule < Msf::Auxiliary

		include Msf::Exploit::Remote::HttpClient

		def initialize(info = {})
			super(update_info(info,
				'Name'           => 'HttpClient Example',
				'Description'    => %q{
					Do a send_request_cgi()
				},
				'Author'         => [ 'sinn3r' ],
				'License'        => MSF_LICENSE
			))

			register_options(
				[
					OptString.new('TARGETURI', [true, 'The base path', '/'])
				], self.class)
		end


		def run
			uri = target_uri.path

			res = send_request_cgi({
				'method'   => 'GET',
				'uri'      => normalize_uri(uri, 'admin', 'index.php'),
				'vars_get' => {
					'p1' => "This is param 1",
					'p2' => "This is param 2"
				}
			})

			if res && res.code == 200
				print_good("I got a 200, awesome")
			else
				print_error("No 200, feeling blue")
			end
		end
	end
```

### Working with Burp Suite

Burp Suite is a useful tool to examine or modify HTTPS traffic while developing a module using HttpClient. To do this:

1. Start Burp: ```java -jar burpsuite.jar```
2. In Burp, click on the Proxies tab, and then Options. Configure the proxy listener there. In this example, let's say we have a listener on port 6666.
3. Once the Burp listener is up, start msfconsole and load the module you're working on.
4. Enter: ```set Proxies HTTP:127.0.0.1:6666```
5. Go ahead and run the module, Burp should intercept the HTTPS traffic.

Note that Burp only supports HTTPS for HttpClient. This problem is only specific to Burp and Metasploit.

If you need to examine HTTP traffic for HttpClient, a workaround is adding the following method in your module. This will override HttpClient's send_request_* method, and return the modified output:

```ruby
def send_request_cgi(opts)
  res = super(opts)
  puts res.request.to_s
  puts
  puts res.to_s
  puts
  puts
end
```

You can do the same for send_request_raw as well.

### Other Common questions:

**1 - Can I use ```vars_get``` and ```vars_post``` together?**

Yes. When you supply a hash to ```vars_get```, basically it means "put all this data in the query string". When you supply a hash to ```vars_post```, it means "put all this data in the body." All of them will be in the same request. You do need to make sure you're using ```send_request_cgi```, of course.

**2 - I can't use ```vars_get``` or ```vars_post``` due to some weird reason, what to do?**

Do mention about this problem in the code (as a comment). If you can't use ```vars_post```, you can try the ```data``` key instead, which will send your post data raw. Normally, the most common solution to get around ```vars_get``` is to leave your stuff in the ```uri``` key. msftidy will flag this, but only as an "Info" and not a warning, which means you should still pass msftidy anyway. If this is a common problem, we can always change msftidy.

**3 - Do I need to manually do basic auth?**

You do not need to manually do basic auth in your request, because HttpClient should automatically do that for you. All you have to do is set the username and password in the datastore options, and then the mixin will use that when the web server asks.

## References

https://github.com/rapid7/metasploit-framework/wiki/How-to-send-an-HTTP-request-using-Rex%3A%3AProto%3A%3AHttp%3A%3AClient