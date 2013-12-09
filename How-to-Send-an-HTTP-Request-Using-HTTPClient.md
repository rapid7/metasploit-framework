This is an example of how to write a module that uses the HttpClient mixin to send a basic HTTP request.

### There are mainly two common functions you will see:

* **send_request_raw()** - You use this to send a raw HTTP request, such as requesting a page.  If you wish to learn about this function, it's better to look at request_raw():
https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb#L133

Here's a basic example of how to use send_request_raw():

```ruby
	send_request_raw({'uri'=>'/index.php'})
```

* **send_request_cgi()** - You use this to send a more advanced HTTP request. For example, if your request contains a query string (or a POST), then you should use this.  If you wish to learn about this function, check out request_cgi():
https://github.com/rapid7/metasploit-framework/blob/master/lib/rex/proto/http/client.rb#L211

By the way, both methods can automaitcally do the HTTP authentication if the user sets the "USERNAME" and "PASSWORD" advanced options.

Here's a very basic example for send_request_cgi():

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

Please note: Either send_request_raw() or send_request_cgi() will return a nil if there's a timeout, so please make sure to account for that condition when you handle the return value.

### URI Parsing

Before you send a HTTP request, you will most likely have to do some URI parsing.  This is a tricky task, because sometimes when you join paths, you may accidentally get double slashes, like this: "/test//index.php".  Or for some reason you have a missing slash.  These are really commonly made mistakes.  So here's how you can handle it safely:

1. Register your default URI datastore option as 'TARGETURI':

Example:

```ruby
	register_options(
		[
			OptString.new('TARGETURI', [true, 'The base path to XXX application', '/xxx_v1/'])
		], self.class)
```

2. Load your TARGETURI with target_uri(), that way you get a real URI object:

In this example, we'll just load the path:

```ruby
	uri = target_uri.path
```

3. When you want to join another URI, always use normalize_uri():

Example:

```ruby
	# Returns: "/xxx_v1/admin/upload.php"
	uri = normalize_uri(uri, 'admin', 'upload.php')
```

4. When you're done normalizing the URI, you're ready to use send_request_cgi() or send_request_raw()

Please note: The normalize_uri() function will always follow these rules:

1. The URI should always begin with a slash.
2. You will have to decide if you need the trailing slash or not.
3. There should be no double slashes.

### Full Example

```ruby

	require 'msf/core'

	class Metasploit3 < Msf::Auxiliary

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
				'uri'      => normalize_uri(uri, 'admin', 'index.phpp'),
				'vars_get' => {
					'p1' => "This is param 1",
					'p2' => "This is param 2"
				}
			})

			if res and res.code == 200
				print_good("I got a 200, awesome")
			else
				print_error("No 200, feeling blue")
			end
		end
	end
```