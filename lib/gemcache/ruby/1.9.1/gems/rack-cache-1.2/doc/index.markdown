__Rack::Cache__ is suitable as a quick drop-in component to enable HTTP caching
for [Rack][]-based applications that produce freshness (`Expires`,
`Cache-Control`) and/or validation (`Last-Modified`, `ETag`) information.

  * Standards-based (see [RFC 2616][rfc] / [Section 13][s13]).
  * Freshness/expiration based caching
  * Validation
  * Vary support
  * Portable: 100% Ruby / works with any [Rack][]-enabled framework.
  * Disk, memcached, and heap memory [storage backends][storage].

News
----

  * Rack::Cache 1.0 was released on December 24, 2010. See the
    [`CHANGES`](http://github.com/rtomayko/rack-cache/blob/1.0/CHANGES) file
    for details.
  * [How to use Rack::Cache with Rails 2.3](http://snippets.aktagon.com/snippets/302-How-to-setup-and-use-Rack-Cache-with-Rails-2-3-0-RC-1) - it's really easy.
  * [RailsLab's Advanced HTTP Caching Screencast](http://railslab.newrelic.com/2009/02/26/episode-11-advanced-http-caching)
    is a really great review of HTTP caching concepts and shows how to
    use Rack::Cache with Rails.

Installation
------------

    $ sudo gem install rack-cache

Or, from a local working copy:

    $ git clone git://github.com/rtomayko/rack-cache.git
    $ rake package && sudo rake install

Basic Usage
-----------

__Rack::Cache__ is implemented as a piece of [Rack][] middleware and can be used
with any __Rack__-based application. If your application includes a rackup
(`.ru`) file or uses __Rack::Builder__ to construct the application pipeline,
simply `require` and `use` as follows:

    require 'rack/cache'

    use Rack::Cache,
      :verbose     => true,
      :metastore   => 'file:/var/cache/rack/meta',
      :entitystore => 'file:/var/cache/rack/body'

    run app

Assuming you've designed your backend application to take advantage of HTTP's
caching features, no further code or configuration is required for basic
caching.

More
----

  * [Configuration Options][config] - how to set cache options.

  * [Cache Storage Documentation][storage] - detailed information on the various
    storage implementations available in __Rack::Cache__ and how to choose the one
    that's best for your application.

  * [Things Caches Do][things] - an illustrated guide to how HTTP gateway
    caches work with pointers to other useful resources on HTTP caching.

  * [GitHub Repository](http://github.com/rtomayko/rack-cache/) - get your
    fork on.

  * [Mailing List](http://groups.google.com/group/rack-cache) - for hackers
    and users (`rack-cache@groups.google.com`).

  * [FAQ](./faq) - Frequently Asked Questions about __Rack::Cache__.

  * [RDoc API Documentation](./api/) - Mostly worthless if you just want to use
    __Rack::Cache__ in your application but mildly insightful if you'd like to
    get a feel for how the system has been put together; I recommend
    [reading the source](http://github.com/rtomayko/rack-cache/tree/master/lib/rack/cache).


See Also
--------

The overall design of __Rack::Cache__ is based largely on the work of the
internet standards community. The following resources provide a good starting
point for exploring the basic concepts of HTTP caching:

  * Mark Nottingham's [Caching Tutorial](http://www.mnot.net/cache_docs/),
    especially the short section on
    [How Web Caches Work](http://www.mnot.net/cache_docs/#WORK)

  * Joe Gregorio's [Doing HTTP Caching Right](http://www.xml.com/lpt/a/1642)

  * [RFC 2616](http://www.ietf.org/rfc/rfc2616.txt), especially
    [Section 13, "Caching in HTTP"](http://www.w3.org/Protocols/rfc2616/rfc2616-sec13.html)

__Rack::Cache__ takes (_liberally_) various concepts from
[Varnish](http://varnish.projects.linpro.no/) and
[Django's cache framework](http://docs.djangoproject.com/en/dev/topics/cache/).

License
-------

__Rack::Cache__ is Copyright &copy; 2008
by [Ryan Tomayko](http://tomayko.com/about)
and is provided under [the MIT license](./license)

[config]:  ./configuration "Rack::Cache Configuration Language Documentation"
[storage]: ./storage       "Rack::Cache Storage Documentation"
[things]:  http://tomayko.com/writings/things-caches-do

[rfc]: http://tools.ietf.org/html/rfc2616
  "RFC 2616 - Hypertext Transfer Protocol -- HTTP/1.1 [ietf.org]"

[s13]: http://tools.ietf.org/html/rfc2616#section-13
  "RFC 2616 / Section 13 Caching in HTTP"

[rack]: http://rack.rubyforge.org/
  "Rack: a Ruby Webserver Interface"

[vcl]: http://tomayko.com/man/vcl
  "VCL(7) -- Varnish Configuration Language Manual Page"
