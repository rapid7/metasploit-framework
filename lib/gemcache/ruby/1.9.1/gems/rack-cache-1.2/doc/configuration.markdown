Configuration
=============

__Rack::Cache__ includes a configuration system that can be used to specify
fairly sophisticated cache policy on a global or per-request basis.

<a id='setopt'></a>

Setting Cache Options
---------------------

Cache options can be set when the __Rack::Cache__ object is created,
or by setting a `rack-cache.<option>` variable in __Rack__'s
__Environment__.

When the __Rack::Cache__ object is instantiated:

    use Rack::Cache,
      :verbose     => true,
      :metastore   => 'memcached://localhost:11211/',
      :entitystore => 'file:/var/cache/rack'

Using __Rack__'s __Environment__:

    env.merge!(
      'rack-cache.verbose' => true,
      'rack-cache.metastore' => 'memcached://localhost:11211/',
      'rack-cache.entitystore' => 'file:/var/cache/rack'
    )

<a id='options'></a>

Cache Option Reference
----------------------

Use the following options to customize __Rack::Cache__:

### `verbose`

Boolean specifying whether verbose trace logging is enabled. This option is
currently enabled (`true`) by default but is likely to be disabled (`false`) in
a future release. All log output is written to the `rack.errors` stream, which
is typically set to `STDERR`.

The `trace`, `info`, `warn`, and `error` methods can be used within the
configuration context to write messages to the errors stream.

### `default_ttl`

An integer specifying the number of seconds a cached object should be considered
"fresh" when no explicit freshness information is provided in a response.
Explicit `Cache-Control` or `Expires` response headers always override this
value. The `default_ttl` option defaults to `0`, meaning responses without
explicit freshness information are considered immediately "stale" and will not
be served from cache without validation.

### `metastore`

A URI specifying the __MetaStore__ implementation used to store request/response
meta information. See the [Rack::Cache Storage Documentation](storage.html)
for detailed information on different storage implementations.

If no metastore is specified, the `heap:/` store is assumed. This implementation
has significant draw-backs so explicit configuration is recommended.

### `entitystore`

A URI specifying the __EntityStore__ implementation used to store
response bodies. See the [Rack::Cache Storage Documentation](storage.html)
for detailed information on different storage implementations.

If no entitystore is specified, the `heap:/` store is assumed. This
implementation has significant draw-backs so explicit configuration is
recommended.

### `private_headers`

An array of request header names that cause the response to be treated with
private cache control semantics. The default value is `['Authorization', 'Cookie']`.
If any of these headers are present in the request, the response is considered
private and will not be cached _unless_ the response is explicitly marked public
(e.g., `Cache-Control: public`).

### `allow_reload`

A boolean specifying whether reload requests sent by the client should be
honored by the cache. When this option is enabled (`rack-cache.allow_reload`
is `true`), requests that include a `Cache-Control: no-cache` header cause
the cache to discard anything it has stored for the request and ask that the
response be fully generated.

Most browsers include a `Cache-Control: no-cache` header when the user performs
a "hard refresh" (e.g., holding `Shift` while clicking the "Refresh" button).

*IMPORTANT: Enabling this option globally allows all clients to break your cache.*

### `allow_revalidate`

A boolean specifying whether revalidate requests sent by the client should be
honored by the cache. When this option is enabled (`rack-cache.allow_revalidate`
is `true`), requests that include a `Cache-Control: max-age=0` header cause the
cache to assume its copy of the response is stale, resulting in a conditional
GET / validation request to be sent to the server.

Most browsers include a `Cache-Control: max-age=0` header when the user performs
a refresh (e.g., clicking the "Refresh" button).

*IMPORTANT: Enabling this option globally allows all clients to break your cache.*

### `cache_key`

A custom cache key generator, which can be anything that responds to :call.
By default, this is the `Rack::Cache::Key` class, but you can implement your own
generator. A cache key generator gets passed a `Rack::Request` object and generates
the appropriate cache key.

The `Rack::Cache::Key` class by default returns the fully qualified url of the request.

In addition to setting the generator to an object, you can just pass a block instead, 
which will act as the cache key generator:
	
	set :cache_key do |request|
		request.fullpath.replace(/\//, '-')
	end
	
For more options see the [Rack::Request documentation](http://rack.rubyforge.org/doc/classes/Rack/Request.html)
	
