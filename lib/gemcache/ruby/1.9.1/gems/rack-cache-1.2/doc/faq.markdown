Frequently Asked Questions
==========================

<p class='intro'>
<strong>NOTE:</strong> This is a work in progress. Please send questions, comments, or
suggestions to <a href="mailto:r@tomayko.com">r@tomayko.com</a>.
</p>

General
-------


<a class='hash' id='rails' href='#rails'>#</a>

### Q: Can I use Rack::Cache with Rails?

Rack::Cache can be used with Rails 2.3 or above. Documentation and a
sample application is forthcoming; in the mean time, see
[this example of using Rack::Cache with Rails 2.3](http://snippets.aktagon.com/snippets/302-How-to-setup-and-use-Rack-Cache-with-Rails-2-3-0-RC-1).

<a class='hash' id='why-not-squid' href='#why-not-squid'>#</a>

### Q: Why Rack::Cache? Why not Squid, Varnish, Perlbol, etc.?

__Rack::Cache__ is often easier to setup as part of your existing Ruby
application than a separate caching system. __Rack::Cache__ runs entirely inside
your backend application processes - no separate / external process is required.
This lets __Rack::Cache__ scale down to development environments and simple
deployments very easily while not sacrificing the benefits of a standards-based
approach to caching.


<a class='hash' id='why-not-rails' href='#why-not-rails'>#</a>

### Q: Why Rack::Cache? Why not use Rails/Merb/FrameworkX's caching system?

__Rack::Cache__ takes a standards-based approach to caching that provides some
benefits over framework-integrated systems.  It uses standard HTTP headers
(`Expires`, `Cache-Control`, `Etag`, `Last-Modified`, etc.) to determine
what/when to cache. Designing applications to support these standard HTTP
mechanisms gives the benefit of being able to switch to a different HTTP
cache implementation in the future.

In addition, using a standards-based approach to caching creates a clear
separation between application and caching logic. The application need only
specify a basic set of information about the response and all decisions
regarding how and when to cache is moved into the caching layer.


<a class='hash' id='scale' href='#scale'>#</a>

### Q: Will Rack::Cache make my app scale?

No. Your design is the only thing that can make your app scale.

Also, __Rack::Cache__ is not overly optimized for performance. The main goal of
the project is to provide a portable, easy-to-configure, and standards-based
caching solution for small to medium sized deployments. More sophisticated /
performant caching systems (e.g., [Varnish][v], [Squid][s],
[httpd/mod-cache][h]) may be more appropriate for large deployments with
crazy-land throughput requirements.

[v]: http://varnish.projects.linpro.no/
[s]: http://www.squid-cache.org/
[h]: http://httpd.apache.org/docs/2.0/mod/mod_cache.html


Features
--------


<a class='hash' id='validation' href='#validation'>#</a>

### Q: Does Rack::Cache support validation?

Yes. Both freshness and validation-based caching is supported. A response
will be cached if it has a freshness lifetime (e.g., `Expires` or
`Cache-Control: max-age=N` headers) and/or includes a validator (e.g.,
`Last-Modified` or `ETag` headers). When the cache hits and the response is
fresh, it's delivered immediately without talking to the backend application;
when the cache is stale, the cached response is validated using a conditional
GET request.


<a class='hash' id='fragments' href='#fragments'>#</a>

### Q: Does Rack::Cache support fragment caching?

Not really. __Rack::Cache__ deals with entire responses and doesn't know
anything about how your application constructs them.

However, something like [ESI](http://www.w3.org/TR/esi-lang) may be implemented
in the future (likely as a separate Rack middleware component that could be
situated upstream from Rack::Cache), which would allow applications to compose
responses based on several "fragment resources". Each fragment would have its
own cache policy.


<a class='hash' id='manual-purge' href='#manual-purge'>#</a>

### Q: How do I manually purge or expire a cached entry?

Although planned, there is currently no mechanism for manually purging
an entry stored in the cache.

Note that using an `Expires` or `Cache-Control: max-age=N` header and relying on
manual purge to invalidate cached entry can often be implemented more simply
using efficient validation based caching (`Last-Modified`, `Etag`). Many web
frameworks are based entirely on manual purge and do not support validation at
the cache level.


<a class='hash' id='force-pass' href='#force-pass'>#</a>

### Q: How do I bypass rack-cache on a per-request basis?

Set the `rack-cache.force-pass` variable in the rack environment to `true`.


<a class='hash' id='efficient-validation' href='#efficient-validation'>#</a>

### Q: What does "Efficient Validation" mean?

It means that your application performs only the processing necessary to
determine if a response is valid before sending a `304 Not Modified` in response
to a conditional GET request.  Many applications that perform validation do so
only after the entire response has been generated, which provides bandwidth
savings but results in no CPU/IO savings.  Implementing validation efficiently
can increase backend application throughput significantly when fronted by a
validating caching system (like __Rack::Cache__).

[Here's an example Rack application](http://gist.github.com/9395) that performs
efficient validation.


<a class='hash' id='orly' href='#orly'>#</a>

### Q: Did you just make that up?

Yes.


<a class='hash' id='https' href='#https'>#</a>

### Q: Can I do HTTPS with Rack::Cache?

Sure. HTTPS is typically managed by a front-end web server so this isn't really
relevant to Rack::Cache.
