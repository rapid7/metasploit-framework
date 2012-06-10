## 0.5

  - Document allow_revalidate and allow_reload options.
  - Support multiple memcache servers.
  - Purge/invalidate everything
  - Explicit expiration/invalidation based on response headers or via an
    object interface passed in the rack env.
  - Sample apps: Rack, Rails, Sinatra, Merb, etc.
  - Move old breakers.rb configuration file into rack-contrib as a
    middleware component.

## Backlog

  - Use Bacon instead of test/spec
  - Fast path pass processing. We do a lot more than necessary just to determine
    that the response should be passed through untouched.
  - Invalidate at the URI of the Location or Content-Location response header
    on POST, PUT, or DELETE that results in a redirect.
  - Maximum size of cached entity
  - Last-Modified factor: requests that have a Last-Modified header but no Expires
    header have a TTL assigned based on the last modified age of the response:
    TTL = (Age * Factor), or, 1h  = (10h * 0.1)
  - Consider implementing ESI (http://www.w3.org/TR/esi-lang). This should
    probably be implemented as a separate middleware component.
  - stale-while-revalidate
  - Serve cached copies when down (see: stale-if-error) - e.g., database
    connection drops and the cache takes over what it can. 
