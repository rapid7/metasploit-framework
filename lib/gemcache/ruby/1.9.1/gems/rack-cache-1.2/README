Rack::Cache
===========

Rack::Cache is suitable as a quick drop-in component to enable HTTP caching for
Rack-based applications that produce freshness (Expires, Cache-Control) and/or
validation (Last-Modified, ETag) information:

  * Standards-based (RFC 2616)
  * Freshness/expiration based caching
  * Validation (If-Modified-Since / If-None-Match)
  * Vary support
  * Cache-Control: public, private, max-age, s-maxage, must-revalidate,
    and proxy-revalidate.
  * Portable: 100% Ruby / works with any Rack-enabled framework
  * Disk, memcached, and heap memory storage backends

For more information about Rack::Cache features and usage, see:

http://tomayko.com/src/rack-cache/

Rack::Cache is not overly optimized for performance. The main goal of the
project is to provide a portable, easy-to-configure, and standards-based
caching solution for small to medium sized deployments. More sophisticated /
high-performance caching systems (e.g., Varnish, Squid, httpd/mod-cache) may be
more appropriate for large deployments with significant throughput requirements.

Installation
------------

From Gem:

    $ sudo gem install rack-cache

With a local working copy:

    $ git clone git://github.com/rtomayko/rack-cache.git
    $ rake package && sudo rake install

Basic Usage
-----------

Rack::Cache is implemented as a piece of Rack middleware and can be used with
any Rack-based application. If your application includes a rackup (`.ru`) file
or uses Rack::Builder to construct the application pipeline, simply require
and use as follows:

    require 'rack/cache'

    use Rack::Cache,
      :metastore   => 'file:/var/cache/rack/meta',
      :entitystore => 'file:/var/cache/rack/body',
      :verbose     => true

    run app

Assuming you've designed your backend application to take advantage of HTTP's
caching features, no further code or configuration is required for basic
caching.

Using with Rails
----------------

Add this to your `config/environment.rb`:

   config.middleware.use Rack::Cache,
       :verbose => true,
       :metastore   => 'file:/var/cache/rack/meta',
       :entitystore => 'file:/var/cache/rack/body'

You should now see `Rack::Cache` listed in the middleware pipeline:

    rake middleware

See the following for more information:

    http://snippets.aktagon.com/snippets/302

Using with Dalli
----------------

Dalli is a high performance memcached client for Ruby.
More information at: https://github.com/mperham/dalli

    require 'dalli'
    require 'rack/cache'

    use Rack::Cache,
      :verbose => true,
      :metastore   => "memcached://localhost:11211/meta",
      :entitystore => "memcached://localhost:11211/body"

    run app

Links
-----

Documentation:
    http://tomayko.com/src/rack-cache/

Mailing List:
    http://groups.google.com/group/rack-cache

GitHub:
    http://github.com/rtomayko/rack-cache/

License
-------

Copyright (c) 2008 Ryan Tomayko <http://tomayko.com/about>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to
deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
