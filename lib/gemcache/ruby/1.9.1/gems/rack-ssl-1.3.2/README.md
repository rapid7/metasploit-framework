Rack::SSL
=========

Force SSL/TLS in your app.

1. Redirects all "http" requests to "https"
2. Set `Strict-Transport-Security` header
3. Flag all cookies as "secure"

Usage
-----

    use Rack::SSL
