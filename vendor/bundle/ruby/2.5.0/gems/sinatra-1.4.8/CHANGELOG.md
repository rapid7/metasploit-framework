= 1.4.7 / 2016-01-24

 * Add Ashley Williams, Trevor Bramble, and Kashyap Kondamudi to team Sinatra.

 * Correctly handle encoded colons in routes. (Jeremy Evans)

 * Rename CHANGES to CHANGELOG.md and update Rakefile. #1043 (Eliza Sorensen)

 * Improve documentation. #941, #1069, #1075, #1025, #1052 (Many great folks)

 * Introduce `Sinatra::Ext` to workaround Rack 1.6 bug to fix Ruby 1.8.7
   support. #1080 (Zachary Scott)

 * Add CONTRIBUTING guide. #987 (Katrina Owen)


= 1.4.6 / 2015-03-23

 * Improve tests and documentation. (Darío Hereñú, Seiichi Yonezawa, kyoendo,
   John Voloski, Ferenc-, Renaud Martinet, Christian Haase, marocchino,
   huoxito, Damir Svrtan, Amaury Medeiros, Jeremy Evans, Kashyap, shenqihui,
   Ausmarton Fernandes, kami, Vipul A M, Lei Wu, 7stud, Taylor Shuler,
   namusyaka, burningTyger, Cornelius Bock, detomastah, hakeda, John Hope,
   Ruben Gonzalez, Andrey Deryabin, attilaolah, Anton Davydov, Nikita Penzin,
   Dyego Costa)

 * Remove duplicate require of sinatra/base. (Alexey Muranov)

 * Escape HTML in 404 error page. (Andy Brody)

 * Refactor to method call in `Stream#close` and `#callback`. (Damir Svrtan)

 * Depend on latest version of Slim. (Damir Svrtan)

 * Fix compatibility with Tilt version 2. (Yegor Timoschenko)

 * Fix compatibility issue with Rack `pretty` method from ShowExceptions.
   (Kashyap)

 * Show date in local time in exception messages. (tayler1)

 * Fix logo on error pages when using Ruby 1.8. (Jeremy Evans)

 * Upgrade test suite to Minitest version 5 and fix Ruby 2.2 compatibility.
   (Vipul A M)

= 1.4.5 / 2014-04-08

 * Improve tests and documentation. (Seiichi Yonezawa, Mike Gehard, Andrew
   Deitrick, Matthew Nicholas Bradley, GoGo tanaka, Carlos Lazo, Shim Tw,
   kyoendo, Roman Kuznietsov, Stanislav Chistenko, Ryunosuke SATO, Ben Lewis,
   wuleicanada, Patricio Mac Adden, Thais Camilo)

 * Fix Ruby warnings. (Vipul A M, Piotr Szotkowski)

 * Fix template cache memory leak. (Scott Holden)

 * Work around UTF-8 bug in JRuby. (namusyaka)

 * Don't set charset for JSON mime-type (Sebastian Borrazas)

 * Fix bug in request.accept? that might trigger a NoMethodError. (sbonami)

= 1.4.4 / 2013-10-21

 * Allow setting layout to false specifically for a single rendering engine.
   (Matt Wildig)

 * Allow using wildcard in argument passed to `request.accept?`. (wilkie)

 * Treat missing Accept header like wild card. (Patricio Mac Adden)

 * Improve tests and documentation. (Darío Javier Cravero, Armen P., michelc,
   Patricio Mac Adden, Matt Wildig, Vipul A M, utenmiki, George Timoschenko,
   Diogo Scudelletti)

 * Fix Ruby warnings. (Vipul A M, Patricio Mac Adden)

 * Improve self-hosted server started by `run!` method or in classic mode.
   (Tobias Bühlmann)

 * Reduce objects allocated per request. (Vipul A M)

 * Drop unused, undocumented options hash from Sinatra.new. (George Timoschenko)

 * Keep Content-Length header when response is a `Rack::File` or when streaming.
   (Patricio Mac Adden, George Timoschenko)

 * Use reel if it's the only server available besides webrick. (Tobias Bühlmann)

 * Add `disable :traps` so setting up signal traps for self hosted server can be
   skipped. (George Timoschenko)

 * The `status` option passed to `send_file` may now be a string. (George
   Timoschenko)

 * Reduce file size of dev mode images for 404 and 500 pages. (Francis Go)

= 1.4.3 / 2013-06-07

 * Running a Sinatra file directly or via `run!` it will now ignore an
   empty $PORT env variable. (noxqsgit)

 * Improve documentation. (burningTyger, Patricio Mac Adden,
   Konstantin Haase, Diogo Scudelletti, Dominic Imhof)

 * Expose matched pattern as env["sinatra.route"]. (Aman Gupta)

 * Fix warning on Ruby 2.0. (Craig Little)

 * Improve running subset of tests in isolation. (Viliam Pucik)

 * Reorder private/public methods. (Patricio Mac Adden)

 * Loosen version dependency for rack, so it runs with Rails 3.2.
   (Konstantin Haase)

 * Request#accept? now returns true instead of a truthy value. (Alan Harris)

= 1.4.2 / 2013-03-21

 * Fix parsing error for case where both the pattern and the captured part
   contain a dot. (Florian Hanke, Konstantin Haase)

 * Missing Accept header is treated like */*. (Greg Denton)

 * Improve documentation. (Patricio Mac Adden, Joe Bottigliero)

= 1.4.1 / 2013-03-15

 * Make delegated methods available in config.ru (Konstantin Haase)

= 1.4.0 / 2013-03-15

 * Add support for LINK and UNLINK requests. (Konstantin Haase)

 * Add support for Yajl templates. (Jamie Hodge)

 * Add support for Rabl templates. (Jesse Cooke)

 * Add support for Wlang templates. (Bernard Lambeau)

 * Add support for Stylus templates. (Juan David Pastas, Konstantin Haase)

 * You can now pass a block to ERb, Haml, Slim, Liquid and Wlang templates,
   which will be used when calling `yield` in the template. (Alexey Muranov)

 * When running in classic mode, no longer include Sinatra::Delegator in Object,
   instead extend the main object only. (Konstantin Haase)

 * Improved route parsing: "/:name.?:format?" with "/foo.png" now matches to
   {name: "foo", format: "png"} instead of {name: "foo.png"}. (Florian Hanke)

 * Add :status option support to send_file. (Konstantin Haase)

 * The `provides` condition now respects an earlier set content type.
   (Konstantin Haase)

 * Exception#code is only used when :use_code is enabled. Moreover, it will
   be ignored if the value is not between 400 and 599. You should use
   Exception#http_status instead. (Konstantin Haase)

 * Status, headers and body will be set correctly in an after filter when using
   halt in a before filter or route. (Konstantin Haase)

 * Sinatra::Base.new now returns a Sinatra::Wrapper instance, exposing
   #settings and #helpers, yet going through the middleware stack on #call.
   It also implements a nice #inspect, so it plays nice with Rails' `rake
   routes`. (Konstantin Haase)

 * In addition to WebRick, Thin and Mongrel, Sinatra will now automatically pick
   up Puma, Trinidad, ControlTower or Net::HTTP::Server when installed. The
   logic for picking the server has been improved and now depends on the Ruby
   implementation used. (Mark Rada, Konstantin Haase, Patricio Mac Adden)

 * "Sinatra doesn't know this ditty" pages now show the app class when running
   a modular application. This helps detecting where the response came from when
   combining multiple modular apps. (Konstantin Haase)

 * When port is not set explicitly, use $PORT env variable if set and only
   default to 4567 if not. Plays nice with foreman. (Konstantin Haase)

 * Allow setting layout on a per engine basis. (Zachary Scott, Konstantin Haase)

 * You can now use `register` directly in a classic app. (Konstantin Haase)

 * `redirect` now accepts URI or Addressable::URI instances. (Nicolas
   Sanguinetti)

 * Have Content-Disposition header also include file name for `inline`, not
   just for `attachment`. (Konstantin Haase)

 * Better compatibility to Rack 1.5. (James Tucker, Konstantin Haase)

 * Make route parsing regex more robust. (Zoltan Dezso, Konstantin Haase)

 * Improve Accept header parsing, expose parameters. (Pieter van de Bruggen,
   Konstantin Haase)

 * Add `layout_options` render option. Allows you, amongst other things, to
   render a layout from a different folder. (Konstantin Haase)

 * Explicitly setting `layout` to `nil` is treated like setting it to `false`.
   (richo)

 * Properly escape attributes in Content-Type header. (Pieter van de Bruggen)

 * Default to only serving localhost in development mode. (Postmodern)

 * Setting status code to 404 in error handler no longer triggers not_found
   handler. (Konstantin Haase)

 * The `protection` option now takes a `session` key for force
   disabling/enabling session based protections. (Konstantin Haase)

 * Add `x_cascade` option to disable `X-Cascade` header on missing route.
   (Konstantin Haase)

 * Improve documentation. (Kashyap, Stanislav Chistenko, Zachary Scott,
   Anthony Accomazzo, Peter Suschlik, Rachel Mehl, ymmtmsys, Anurag Priyam,
   burningTyger, Tony Miller, akicho8, Vasily Polovnyov, Markus Prinz,
   Alexey Muranov, Erik Johnson, Vipul A M, Konstantin Haase)

 * Convert documentation to Markdown. (Kashyap, Robin Dupret, burningTyger,
   Vasily Polovnyov, Iain Barnett, Giuseppe Capizzi, Neil West)

 * Don't set not_found content type to HTML in development mode with custom
   not_found handler. (Konstantin Haase)

 * Fix mixed indentation for private methods. (Robin Dupret)

 * Recalculate Content-Length even if hard coded if body is reset. Relevant
   mostly for error handlers. (Nathan Esquenazi, Konstantin Haase)

 * Plus sign is once again kept as such when used for URL matches. (Konstantin
   Haase)

 * Take views option into account for template caching. (Konstantin Haase)

 * Consistent use of `headers` instead of `header` internally. (Patricio Mac Adden)

 * Fix compatibility to RDoc 4. (Bohuslav Kabrda)

 * Make chat example work with latest jQuery. (loveky, Tony Miller)

 * Make tests run without warnings. (Patricio Mac Adden)

 * Make sure value returned by `mime_type` is a String or nil, even when a
   different object is passed in, like an AcceptEntry. (Konstantin Haase)

 * Exceptions in `after` filter are now handled like any other exception.
   (Nathan Esquenazi)

= 1.3.6 (backport release) / 2013-03-15

Backported from 1.4.0:

 * Take views option into account for template caching. (Konstantin Haase)

 * Improve documentation (Konstantin Haase)

 * No longer override `define_singleton_method`. (Konstantin Haase)

= 1.3.5 / 2013-02-25

 * Fix for RubyGems 2.0 (Uchio KONDO)

 * Improve documentation (Konstantin Haase)

 * No longer override `define_singleton_method`. (Konstantin Haase)

= 1.3.4 / 2013-01-26

 * Improve documentation. (Kashyap, Stanislav Chistenko, Konstantin Haase,
   ymmtmsys, Anurag Priyam)

 * Adjustments to template system to work with Tilt edge. (Konstantin Haase)

 * Fix streaming with latest Rack release. (Konstantin Haase)

 * Fix default content type for Sinatra::Response with latest Rack release.
   (Konstantin Haase)

 * Fix regression where + was no longer treated like space. (Ross Boucher)

 * Status, headers and body will be set correctly in an after filter when using
   halt in a before filter or route. (Konstantin Haase)

= 1.3.3 / 2012-08-19

 * Improved documentation. (burningTyger, Konstantin Haase, Gabriel Andretta,
   Anurag Priyam, michelc)

 * No longer modify the load path. (Konstantin Haase)

 * When keeping a stream open, set up callback/errback correctly to deal with
   clients closing the connection. (Konstantin Haase)

 * Fix bug where having a query param and a URL param by the same name would
   concatenate the two values. (Konstantin Haase)

 * Prevent duplicated log output when application is already wrapped in a
   `Rack::CommonLogger`. (Konstantin Haase)

 * Fix issue where `Rack::Link` and Rails were preventing indefinite streaming.
   (Konstantin Haase)

 * No longer cause warnings when running Ruby with `-w`. (Konstantin Haase)

 * HEAD requests on static files no longer report a Content-Length of 0, but
   instead the proper length. (Konstantin Haase)

 * When protecting against CSRF attacks, drop the session instead of refusing
   the request. (Konstantin Haase)

= 1.3.2 / 2011-12-30

 * Don't automatically add `Rack::CommonLogger` if `Rack::Server` is adding it,
   too. (Konstantin Haase)

 * Setting `logging` to `nil` will avoid setting up `Rack::NullLogger`.
   (Konstantin Haase)

 * Route specific params are now available in the block passed to #stream.
   (Konstantin Haase)

 * Fix bug where rendering a second template in the same request, after the
   first one raised an exception, skipped the default layout. (Nathan Baum)

 * Fix bug where parameter escaping got enabled when disabling a different
   protection. (Konstantin Haase)

 * Fix regression: Filters without a pattern may now again manipulate the params
   hash. (Konstantin Haase)

 * Added examples directory. (Konstantin Haase)

 * Improved documentation. (Gabriel Andretta, Markus Prinz, Erick Zetta, Just
   Lest, Adam Vaughan, Aleksander Dąbrowski)

 * Improved MagLev support. (Tim Felgentreff)

= 1.3.1 / 2011-10-05

 * Support adding more than one callback to the stream object. (Konstantin
   Haase)

 * Fix for infinite loop when streaming on 1.9.2 with Thin from a modular
   application (Konstantin Haase)

= 1.3.0 / 2011-09-30

 * Added `stream` helper method for easily creating streaming APIs, Server
   Sent Events or even WebSockets. See README for more on that topic.
   (Konstantin Haase)

 * If a HTTP 1.1 client is redirected from a different verb than GET, use 303
   instead of 302 by default. You may still pass 302 explicitly. Fixes AJAX
   redirects in Internet Explorer 9 (to be fair, everyone else is doing it
   wrong and IE is behaving correct). (Konstantin Haase)

 * Added support for HTTP PATCH requests. (Konstantin Haase)

 * Use rack-protection to defend against common opportunistic attacks.
   (Josh Lane, Jacob Burkhart, Konstantin Haase)

 * Support for Creole templates, Creole is a standardized wiki markup,
   supported by many wiki implementations. (Konstanin Haase)

 * The `erubis` method has been deprecated. If Erubis is available, Sinatra
   will automatically use it for rendering ERB templates. `require 'erb'`
   explicitly to prevent that behavior. (Magnus Holm, Ryan Tomayko, Konstantin
   Haase)

 * Patterns now match against the escaped URLs rather than the unescaped
   version. This makes Sinatra confirm with RFC 2396 section 2.2 and RFC 2616
   section 3.2.3 (escaped reserved characters should not be treated like the
   unescaped version), meaning that "/:name" will also match `/foo%2Fbar`, but
   not `/foo/bar`. To avoid incompatibility, pattern matching has been
   adjusted. Moreover, since we do no longer need to keep an unescaped version
   of path_info around, we handle all changes to `env['PATH_INFO']` correctly.
   (Konstantin Haase)

 * `settings.app_file` now defaults to the file subclassing `Sinatra::Base` in
   modular applications. (Konstantin Haase)

 * Set up `Rack::Logger` or `Rack::NullLogger` depending on whether logging
   was enabled or not. Also, expose that logger with the `logger` helper
   method. (Konstantin Haase)

 * The sessions setting may be an options hash now. (Konstantin Haase)

 * Important: Ruby 1.8.6 support has been dropped. This version also depends
   on at least Rack 1.3.0. This means that it is incompatible with Rails prior
   to 3.1.0. Please use 1.2.x if you require an earlier version of Ruby or
   Rack, which we will continue to supply with bug fixes. (Konstantin Haase)

 * Renamed `:public` to `:public_folder` to avoid overriding Ruby's built-in
   `public` method/keyword. `set(:public, ...)` is still possible but shows a
   warning. (Konstantin Haase)

 * It is now possible to use a different target class for the top level DSL
   (aka classic style) than `Sinatra::Application` by setting
   `Delegator.target`. This was mainly introduced to ease testing. (Konstantin
   Haase)

 * Error handlers defined for an error class will now also handle subclasses
   of that class, unless more specific error handlers exist. (Konstantin
   Haase)

 * Error handling respects Exception#code, again. (Konstantin Haase)

 * Changing a setting will merge hashes: `set(:x, :a => 1); set(:x :b => 2)`
   will result in `{:a => 1, :b => 2}`. Use `set(:x, {:a => 1}, true)` to
   avoid this behavior. (Konstantin Haase)

 * Added `request.accept?` and `request.preferred_type` to ease dealing with
   `Accept` headers. (Konstantin Haase)

 * Added `:static_cache_control` setting to automatically set cache control
   headers to static files. (Kenichi Nakamura)

 * Added `informal?`, `success?`, `redirect?`, `client_error?`,
   `server_error?` and `not_found?` helper methods to ease dealing with status
   codes. (Konstantin Haase)

 * Uses SecureRandom to generate default session secret. (Konstantin Haase)

 * The `attachment` helper will set Content-Type (if it hasn't been set yet)
   depending on the supplied file name. (Vasiliy Ermolovich)

 * Conditional requests on `etag` helper now work properly for unsafe HTTP
   methods. (Matthew Schinckel, Konstantin Haase)

 * The `last_modified` helper does not stop execution and change the status code
   if the status code is something different than 200. (Konstantin Haase)

 * Added support for If-Unmodified-Since header. (Konstantin Haase)

 * `Sinatra::Base.run!` now prints to stderr rather than stdout. (Andrew
   Armenia)

 * `Sinatra::Base.run!` takes a block allowing access to the Rack handler.
   (David Waite)

 * Automatic `app_file` detection now works in directories containing brackets
   (Konstantin Haase)

 * Exception objects are now passed to error handlers. (Konstantin Haase)

 * Improved documentation. (Emanuele Vicentini, Peter Higgins, Takanori
   Ishikawa, Konstantin Haase)

 * Also specify charset in Content-Type header for JSON. (Konstantin Haase)

 * Rack handler names will not be converted to lower case internally, this
   allows you to run Sinatra with custom Rack handlers, like Kirk or Mongrel2.
   Example: `ruby app.rb -s Mongrel2` (Konstantin Haase)

 * Ignore `to_ary` on response bodies. Fixes compatibility to Rails 3.1.
   (Konstantin Haase)

 * Middleware setup is now distributed across multiple methods, allowing
   Sinatra extensions to easily hook into the setup process. (Konstantin
   Haase)

 * Internal refactoring and minor performance improvements. (Konstantin Haase)

 * Move Sinatra::VERSION to separate file, so it can be checked without
   loading Sinatra. (Konstantin Haase)

 * Command line options now complain if value passed to `-p` is not a valid
   integer. (Konstantin Haase)

 * Fix handling of broken query params when displaying exceptions. (Luke
   Jahnke)

= 1.2.9 (backports release) / 2013-03-15

IMPORTANT: THIS IS THE LAST 1.2.x RELEASE, PLEASE UPGRADE.

 * Display EOL warning when loading Sinatra. (Konstantin Haase)

 * Improve documentation. (Anurag Priyam, Konstantin Haase)

 * Do not modify the load path. (Konstantin Haase)

 * Display deprecation warning if RUBY_IGNORE_CALLERS is used. (Konstantin Haase)

 * Add backports library so we can still run on Ruby 1.8.6. (Konstantin Haase)

= 1.2.8 (backports release) / 2011-12-30

Backported from 1.3.2:

* Fix bug where rendering a second template in the same request after the
  first one raised an exception skipped the default layout (Nathan Baum)

= 1.2.7 (backports release) / 2011-09-30

Custom changes:

 * Fix Ruby 1.8.6 issue with Accept header parsing. (Konstantin Haase)

Backported from 1.3.0:

 * Ignore `to_ary` on response bodies. Fixes compatibility to Rails 3.1.
   (Konstantin Haase)

 * `Sinatra.run!` now prints to stderr rather than stdout. (Andrew Armenia)

 * Automatic `app_file` detection now works in directories containing brackets
   (Konstantin Haase)

 * Improved documentation. (Emanuele Vicentini, Peter Higgins, Takanori
   Ishikawa, Konstantin Haase)

 * Also specify charset in Content-Type header for JSON. (Konstantin Haase)

 * Rack handler names will not be converted to lower case internally, this
   allows you to run Sinatra with custom Rack handlers, like Kirk or Mongrel2.
   Example: `ruby app.rb -s Mongrel2` (Konstantin Haase)

 * Fix uninitialized instance variable warning. (David Kellum)

 * Command line options now complain if value passed to `-p` is not a valid
   integer. (Konstantin Haase)

 * Fix handling of broken query params when displaying exceptions. (Luke
   Jahnke)

= 1.2.6 / 2011-05-01

 * Fix broken delegation, backport delegation tests from Sinatra 1.3.
   (Konstantin Haase)

= 1.2.5 / 2011-04-30

 * Restore compatibility with Ruby 1.8.6. (Konstantin Haase)

= 1.2.4 / 2011-04-30

 * Sinatra::Application (classic style) does not use a session secret in
   development mode, so sessions are not invalidated after every request when
   using Shotgun. (Konstantin Haase)

 * The request object was shared between multiple Sinatra instances in the
   same middleware chain. This caused issues if any non-sinatra routing
   happend in-between two of those instances, or running a request twice
   against an application (described in the README). The caching was reverted.
   See GH#239 and GH#256 for more infos. (Konstantin Haase)

 * Fixes issues where the top level DSL was interfering with method_missing
   proxies. This issue surfaced when Rails 3 was used with older Sass versions
   and Sinatra >= 1.2.0. (Konstantin Haase)

 * Sinatra::Delegator.delegate is now able to delegate any method names, even
   those containing special characters. This allows better integration into
   other programming languages on Rubinius (probably on the JVM, too), like
   Fancy. (Konstantin Haase)

 * Remove HEAD request logic and let Rack::Head handle it instead. (Paolo
   "Nusco" Perrotta)

= 1.2.3 / 2011-04-13

 * This release is compatible with Tilt 1.3, it will still work with Tilt 1.2.2,
   however, if you want to use a newer Tilt version, you have to upgrade to at
   least this version of Sinatra. (Konstantin Haase)

 * Helpers dealing with time, like `expires`, handle objects that pretend to be
   numbers, like `ActiveSupport::Duration`, better. (Konstantin Haase)

= 1.2.2 / 2011-04-08

 * The `:provides => :js` condition now matches both `application/javascript`
   and `text/javascript`. The `:provides => :xml` condition now matches both
   `application/xml` and `text/xml`. The `Content-Type` header is set
   accordingly. If the client accepts both, the `application/*` version is
   preferred, since the `text/*` versions are deprecated. (Konstantin Haase)

 * The `provides` condition now handles wildcards in `Accept` headers correctly.
   Thus `:provides => :html` matches `text/html`, `text/*` and `*/*`.
   (Konstantin Haase)

 * When parsing `Accept` headers, `Content-Type` preferences are honored
   according to RFC 2616 section 14.1. (Konstantin Haase)

 * URIs passed to the `url` helper or `redirect` may now use any schema to be
   identified as absolute URIs, not only `http` or `https`. (Konstantin Haase)

 * Handles `Content-Type` strings that already contain parameters correctly in
   `content_type` (example: `content_type "text/plain; charset=utf-16"`).
   (Konstantin Haase)

 * If a route with an empty pattern is defined (`get("") { ... }`) requests with
   an empty path info match this route instead of "/". (Konstantin Haase)

 * In development environment, when running under a nested path, the image URIs
   on the error pages are set properly. (Konstantin Haase)

= 1.2.1 / 2011-03-17

 * Use a generated session secret when using `enable :sessions`. (Konstantin
   Haase)

 * Fixed a bug where the wrong content type was used if no content type was set
   and a template engine was used with a different engine for the layout with
   different default content types, say Less embedded in Slim. (Konstantin
   Haase)

 * README translations improved (Gabriel Andretta, burningTyger, Sylvain Desvé,
   Gregor Schmidt)

= 1.2.0 / 2011-03-03

 * Added `slim` rendering method for rendering Slim templates. (Steve
   Hodgkiss)

 * The `markaby` rendering method now allows passing a block, making inline
   usage possible. Requires Tilt 1.2 or newer. (Konstantin Haase)

 * All render methods now take a `:layout_engine` option, allowing to use a
   layout in a different template language. Even more useful than using this
   directly (`erb :index, :layout_engine => :haml`) is setting this globally for
   a template engine that otherwise does not support layouts, like Markdown or
   Textile (`set :markdown, :layout_engine => :erb`). (Konstantin Haase)

 * Before and after filters now support conditions, both with and without
   patterns (`before '/api/*', :agent => /Songbird/`). (Konstantin Haase)

 * Added a `url` helper method which constructs absolute URLs. Copes with
   reverse proxies and Rack handlers correctly. Aliased to `to`, so you can
   write `redirect to('/foo')`. (Konstantin Haase)

 * If running on 1.9, patterns for routes and filters now support named
   captures: `get(%r{/hi/(?<name>[^/?#]+)}) { "Hi #{params['name']}" }`.
   (Steve Price)

 * All rendering methods now take a `:scope` option, which renders them in
   another context. Note that helpers and instance variables will be
   unavailable if you use this feature. (Paul Walker)

 * The behavior of `redirect` can now be configured with `absolute_redirects`
   and `prefixed_redirects`. (Konstantin Haase)

 * `send_file` now allows overriding the Last-Modified header, which defaults
   to the file's mtime, by passing a `:last_modified` option. (Konstantin Haase)

 * You can use your own template lookup method by defining `find_template`.
   This allows, among other things, using more than one views folder.
   (Konstantin Haase)

 * Largely improved documentation. (burningTyger, Vasily Polovnyov, Gabriel
   Andretta, Konstantin Haase)

 * Improved error handling. (cactus, Konstantin Haase)

 * Skip missing template engines in tests correctly. (cactus)

 * Sinatra now ships with a Gemfile for development dependencies, since it eases
   supporting different platforms, like JRuby. (Konstantin Haase)

= 1.1.4 (backports release) / 2011-04-13

 * Compatible with Tilt 1.3. (Konstantin Haase)

= 1.1.3 / 2011-02-20

 * Fixed issues with `user_agent` condition if the user agent header is missing.
   (Konstantin Haase)

 * Fix some routing tests that have been skipped by accident (Ross A. Baker)

 * Fix rendering issues with Builder and Nokogiri (Konstantin Haase)

 * Replace last_modified helper with better implementation. (cactus,
   Konstantin Haase)

 * Fix issue with charset not being set when using `provides` condition.
   (Konstantin Haase)

 * Fix issue with `render` not picking up all alternative file extensions for
   a rendering engine - it was not possible to register ".html.erb" without
   tricks. (Konstantin Haase)

= 1.1.2 / 2010-10-25

Like 1.1.1, but with proper CHANGES file.

= 1.1.1 / 2010-10-25

 * README has been translated to Russian (Nickolay Schwarz, Vasily Polovnyov)
   and Portuguese (Luciano Sousa).

 * Nested templates without a `:layout` option can now be used from the layout
   template without causing an infinite loop. (Konstantin Haase)

 * Inline templates are now encoding aware and can therefore be used with
   unicode characters on Ruby 1.9. Magic comments at the beginning of the file
   will be honored. (Konstantin Haase)

 * Default `app_file` is set correctly when running with bundler. Using
   bundler caused Sinatra not to find the `app_file` and therefore not to find
   the `views` folder on it's own. (Konstantin Haase)

 * Better handling of Content-Type when using `send_file`: If file extension
   is unknown, fall back to `application/octet-stream` and do not override
   content type if it has already been set, except if `:type` is passed
   explicitly (Konstantin Haase)

 * Path is no longer cached if changed between handlers that do pattern
   matching. This means you can change `request.path_info` in a pattern
   matching before filter. (Konstantin Haase)

 * Headers set by cache_control now always set max_age as an Integer, making
   sure it is compatible with RFC2616. (Konstantin Haase)

 * Further improved handling of string encodings on Ruby 1.9, templates now
   honor default_encoding and URLs support unicode characters. (Konstantin
   Haase)

= 1.1.0 / 2010-10-24

 * Before and after filters now support pattern matching, including the
   ability to use captures: "before('/user/:name') { |name| ... }". This
   avoids manual path checking. No performance loss if patterns are avoided.
   (Konstantin Haase)

 * It is now possible to render SCSS files with the `scss` method, which
   behaves exactly like `sass` except for the different file extension and
   assuming the SCSS syntax. (Pedro Menezes, Konstantin Haase)

 * Added `liquid`, `markdown`, `nokogiri`, `textile`, `rdoc`, `radius`,
   `markaby`, and `coffee` rendering methods for rendering Liquid, Markdown,
   Nokogiri, Textile, RDoc, Radius, Markaby and CoffeeScript templates.
   (Konstantin Haase)

 * Now supports byte-range requests (the HTTP_RANGE header) for static files.
   Multi-range requests are not supported, however. (Jens Alfke)

 * You can now use #settings method from class and top level for convenience.
   (Konstantin Haase)

 * Setting multiple values now no longer relies on #to_hash and therefore
   accepts any Enumerable as parameter. (Simon Rozet)

 * Nested templates default the `layout` option to `false` rather than `true`.
   This eases the use of partials. If you wanted to render one haml template
   embedded in another, you had to call `haml :partial, {}, :layout => false`.
   As you almost never want the partial to be wrapped in the standard layout
   in this situation, you now only have to call `haml :partial`. Passing in
   `layout` explicitly is still possible. (Konstantin Haase)

 * If a the return value of one of the render functions is used as a response
   body and the content type has not been set explicitly, Sinatra chooses a
   content type corresponding to the rendering engine rather than just using
   "text/html". (Konstantin Haase)

 * README is now available in Chinese (Wu Jiang), French (Mickael Riga),
   German (Bernhard Essl, Konstantin Haase, burningTyger), Hungarian (Janos
   Hardi) and Spanish (Gabriel Andretta). The extremely outdated Japanese
   README has been updated (Kouhei Yanagita).

 * It is now possible to access Sinatra's template_cache from the outside.
   (Nick Sutterer)

 * The `last_modified` method now also accepts DateTime instances and makes
   sure the header will always be set to a string. (Konstantin Haase)

 * 599 now is a legal status code. (Steve Shreeve)

 * This release is compatible with Ruby 1.9.2. Sinatra was trying to read
   non existent files Ruby added to the call stack. (Shota Fukumori,
   Konstantin Haase)

 * Prevents a memory leak on 1.8.6 in production mode. Note, however, that
   this is due to a bug in 1.8.6 and request will have the additional overhead
   of parsing templates again on that version. It is recommended to use at
   least Ruby 1.8.7. (Konstantin Haase)

 * Compares last modified date correctly. `last_modified` was halting only
   when the 'If-Modified-Since' header date was equal to the time specified.
   Now, it halts when is equal or later than the time specified (Gabriel
   Andretta).

 * Sinatra is now usable in combination with Rails 3. When mounting a Sinatra
   application under a subpath in Rails 3, the PATH_INFO is not prefixed with
   a slash and no routes did match. (José Valim)

 * Better handling of encodings in 1.9, defaults params encoding to UTF-8.
   (Konstantin Haase)

 * `show_exceptions` handling is now triggered after custom error handlers, if
   it is set to `:after_handlers`, thus not disabling those handler in
   development mode. (pangel, Konstantin Haase)

 * Added ability to handle weighted HTTP_ACCEPT headers. (Davide D'Agostino)

 * `send_file` now always respects the `:type` option if set. Previously it
   was discarded if no matching mime type was found, which made it impossible
   to directly pass a mime type. (Konstantin Haase)

 * `redirect` always redirects to an absolute URI, even if a relative URI was
   passed. Ensures compatibility with RFC 2616 section 14.30. (Jean-Philippe
   Garcia Ballester, Anthony Williams)

 * Broken examples for using Erubis, Haml and Test::Unit in README have been
   fixed. (Nick Sutterer, Doug Ireton, Jason Stewart, Eric Marden)

 * Sinatra now handles SIGTERM correctly. (Patrick Collison)

 * Fixes an issue with inline templates in modular applications that manually
   call `run!`. (Konstantin Haase)

 * Spaces after inline template names are now ignored (Konstantin Haase)

 * It's now possible to use Sinatra with different package management
   systems defining a custom require. (Konstantin Haase)

 * Lighthouse has been dropped in favor of GitHub issues.

 * Tilt is now a dependency and therefore no longer ships bundled with
   Sinatra. (Ryan Tomayko, Konstantin Haase)

 * Sinatra now depends on Rack 1.1 or higher. Rack 1.0 is no longer supported.
   (Konstantin Haase)

= 1.0 / 2010-03-23

 * It's now possible to register blocks to run after each request using
   after filters. After filters run at the end of each request, after
   routes and error handlers. (Jimmy Schementi)

 * Sinatra now uses Tilt <http://github.com/rtomayko/tilt> for rendering
   templates. This adds support for template caching, consistent
   template backtraces, and support for new template engines, like
   mustache and liquid. (Ryan Tomayko)

 * ERB, Erubis, and Haml templates are now compiled the first time
   they're rendered instead of being string eval'd on each invocation.
   Benchmarks show a 5x-10x improvement in render time. This also
   reduces the number of objects created, decreasing pressure on Ruby's
   GC. (Ryan Tomayko)

 * New 'settings' method gives access to options in both class and request
   scopes. This replaces the 'options' method. (Chris Wanstrath)

 * New boolean 'reload_templates' setting controls whether template files
   are reread from disk and recompiled on each request. Template read/compile
   is cached by default in all environments except development. (Ryan Tomayko)

 * New 'erubis' helper method for rendering ERB template with Erubis. The
   erubis gem is required. (Dylan Egan)

 * New 'cache_control' helper method provides a convenient way of
   setting the Cache-Control response header. Takes a variable number
   of boolean directives followed by a hash of value directives, like
   this: cache_control :public, :must_revalidate, :max_age => 60
   (Ryan Tomayko)

 * New 'expires' helper method is like cache_control but takes an
   integer number of seconds or Time object:
   expires 300, :public, :must_revalidate
   (Ryan Tomayko)

 * New request.secure? method for checking for an SSL connection.
   (Adam Wiggins)

 * Sinatra apps can now be run with a `-o <addr>` argument to specify
   the address to bind to. (Ryan Tomayko)

 * Rack::Session::Cookie is now added to the middleware pipeline when
   running in test environments if the :sessions option is set.
   (Simon Rozet)

 * Route handlers, before filters, templates, error mappings, and
   middleware are now resolved dynamically up the inheritance hierarchy
   when needed instead of duplicating the superclass's version when
   a new Sinatra::Base subclass is created. This should fix a variety
   of issues with extensions that need to add any of these things
   to the base class. (Ryan Tomayko)

 * Exception error handlers always override the raise_errors option now.
   Previously, all exceptions would be raised outside of the application
   when the raise_errors option was enabled, even if an error handler was
   defined for that exception. The raise_errors option now controls
   whether unhandled exceptions are raised (enabled) or if a generic 500
   error is returned (disabled). (Ryan Tomayko)

 * The X-Cascade response header is set to 'pass' when no matching route
   is found or all routes pass. (Josh Peek)

 * Filters do not run when serving static files anymore. (Ryan Tomayko)

 * pass takes an optional block to be used as the route handler if no
   subsequent route matches the request. (Blake Mizerany)

The following Sinatra features have been obsoleted (removed entirely) in
the 1.0 release:

 * The `sinatra/test` library is obsolete. This includes the `Sinatra::Test`
   module, the `Sinatra::TestHarness` class, and the `get_it`, `post_it`,
   `put_it`, `delete_it`, and `head_it` helper methods. The
   [`Rack::Test` library](http://gitrdoc.com/brynary/rack-test) should
   be used instead.

 * Test framework specific libraries (`sinatra/test/spec`,
   `sinatra/test/bacon`,`sinatra/test/rspec`, etc.) are obsolete. See
   http://www.sinatrarb.com/testing.html for instructions on setting up a
   testing environment under each of these frameworks.

 * `Sinatra::Default` is obsolete; use `Sinatra::Base` instead.
   `Sinatra::Base` acts more like `Sinatra::Default` in development mode.
   For example, static file serving and sexy development error pages are
   enabled by default.

 * Auto-requiring template libraries in the `erb`, `builder`, `haml`,
   and `sass` methods is obsolete due to thread-safety issues. You must
   require the template libraries explicitly in your app.

 * The `:views_directory` option to rendering methods is obsolete; use
   `:views` instead.

 * The `:haml` and `:sass` options to rendering methods are obsolete.
   Template engine options should be passed in the second Hash argument
   instead.

 * The `use_in_file_templates` method is obsolete. Use
   `enable :inline_templates` or `set :inline_templates, 'path/to/file'`

 * The 'media_type' helper method is obsolete. Use 'mime_type' instead.

 * The 'mime' main and class method is obsolete. Use 'mime_type' instead.

 * The request-level `send_data` method is no longer supported.

 * The `Sinatra::Event` and `Sinatra::EventContext` classes are no longer
   supported. This may effect extensions written for versions prior to 0.9.2.
   See [Writing Sinatra Extensions](http://www.sinatrarb.com/extensions.html)
   for the officially supported extensions API.

 * The `set_option` and `set_options` methods are obsolete; use `set`
   instead.

 * The `:env` setting (`settings.env`) is obsolete; use `:environment`
   instead.

 * The request level `stop` method is obsolete; use `halt` instead.

 * The request level `entity_tag` method is obsolete; use `etag`
   instead.

 * The request level `headers` method (HTTP response headers) is obsolete;
   use `response['Header-Name']` instead.

 * `Sinatra.application` is obsolete; use `Sinatra::Application` instead.

 * Using `Sinatra.application = nil` to reset an application is obsolete.
   This should no longer be necessary.

 * Using `Sinatra.default_options` to set base configuration items is
   obsolete; use `Sinatra::Base.set(key, value)` instead.

 * The `Sinatra::ServerError` exception is obsolete. All exceptions raised
   within a request are now treated as internal server errors and result in
   a 500 response status.

 * The `:methodoverride' option to enable/disable the POST _method hack is
   obsolete; use `:method_override` instead.

= 0.9.2 / 2009-05-18

 * This version is compatible with Rack 1.0. [Rein Henrichs]

 * The development-mode unhandled exception / error page has been
   greatly enhanced, functionally and aesthetically. The error
   page is used when the :show_exceptions option is enabled and an
   exception propagates outside of a route handler or before filter.
   [Simon Rozet / Matte Noble / Ryan Tomayko]

 * Backtraces that move through templates now include filenames and
   line numbers where possible. [#51 / S. Brent Faulkner]

 * All templates now have an app-level option for setting default
   template options (:haml, :sass, :erb, :builder). The app-level
   option value must be a Hash if set and is merged with the
   template options specified to the render method (Base#haml,
   Base#erb, Base#builder). [S. Brent Faulkner, Ryan Tomayko]

 * The method signature for all template rendering methods has
   been unified: "def engine(template, options={}, locals={})".
   The options Hash now takes the generic :views, :layout, and
   :locals options but also any template-specific options. The
   generic options are removed before calling the template specific
   render method. Locals may be specified using either the
   :locals key in the options hash or a second Hash option to the
   rendering method. [#191 / Ryan Tomayko]

 * The receiver is now passed to "configure" blocks. This
   allows for the following idiom in top-level apps:
   configure { |app| set :foo, app.root + '/foo' }
   [TJ Holowaychuck / Ryan Tomayko]

 * The "sinatra/test" lib is deprecated and will be removed in
   Sinatra 1.0. This includes the Sinatra::Test module and
   Sinatra::TestHarness class in addition to all the framework
   test helpers that were deprecated in 0.9.1. The Rack::Test
   lib should be used instead: http://gitrdoc.com/brynary/rack-test
   [#176 / Simon Rozet]

 * Development mode source file reloading has been removed. The
   "shotgun" (http://rtomayko.github.com/shotgun/) program can be
   used to achieve the same basic functionality in most situations.
   Passenger users should use the "tmp/always_restart.txt"
   file (http://tinyurl.com/c67o4h). [#166 / Ryan Tomayko]

 * Auto-requiring template libs in the erb, builder, haml, and
   sass methods is deprecated due to thread-safety issues. You must
   require the template libs explicitly in your app file. [Simon Rozet]

 * A new Sinatra::Base#route_missing method was added. route_missing
   is sent when no route matches the request or all route handlers
   pass.  The default implementation forwards the request to the
   downstream app when running as middleware (i.e., "@app" is
   non-nil), or raises a NotFound exception when no downstream app
   is defined. Subclasses can override this method to perform custom
   route miss logic. [Jon Crosby]

 * A new Sinatra::Base#route_eval method was added. The method
   yields to the block and throws :halt with the result. Subclasses
   can override this method to tap into the route execution logic.
   [TJ Holowaychuck]

 * Fix the "-x" (enable request mutex / locking) command line
   argument. Passing -x now properly sets the :lock option.
   [S. Brent Faulkner, Ryan Tomayko]

 * Fix writer ("foo=") and predicate ("foo?") methods in extension
   modules not being added to the registering class.
   [#172 / Pat Nakajima]

 * Fix in-file templates when running alongside activesupport and
   fatal errors when requiring activesupport before sinatra
   [#178 / Brian Candler]

 * Fix various issues running on Google AppEngine.
   [Samuel Goebert, Simon Rozet]

 * Fix in-file templates __END__ detection when __END__ exists with
   other stuff on a line [Yoji Shidara]

= 0.9.1.1 / 2009-03-09

 * Fix directory traversal vulnerability in default static files
   route. See [#177] for more info.

= 0.9.1 / 2009-03-01

 * Sinatra now runs under Ruby 1.9.1 [#61]

 * Route patterns (splats, :named, or Regexp captures) are now
   passed as arguments to the block. [#140]

 * The "helpers" method now takes a variable number of modules
   along with the normal block syntax. [#133]

 * New request-level #forward method for middleware components: passes
   the env to the downstream app and merges the response status, headers,
   and body into the current context. [#126]

 * Requests are now automatically forwarded to the downstream app when
   running as middleware and no matching route is found or all routes
   pass.

 * New simple API for extensions/plugins to add DSL-level and
   request-level methods. Use Sinatra.register(mixin) to extend
   the DSL with all public methods defined in the mixin module;
   use Sinatra.helpers(mixin) to make all public methods defined
   in the mixin module available at the request level. [#138]
   See http://www.sinatrarb.com/extensions.html for details.

 * Named parameters in routes now capture the "." character. This makes
   routes like "/:path/:filename" match against requests like
   "/foo/bar.txt"; in this case, "params[:filename]" is "bar.txt".
   Previously, the route would not match at all.

 * Added request-level "redirect back" to redirect to the referring
   URL.

 * Added a new "clean_trace" option that causes backtraces dumped
   to rack.errors and displayed on the development error page to
   omit framework and core library backtrace lines. The option is
   enabled by default. [#77]

 * The ERB output buffer is now available to helpers via the @_out_buf
   instance variable.

 * It's now much easier to test sessions in unit tests by passing a
   ":session" option to any of the mock request methods. e.g.,
       get '/', {}, :session => { 'foo' => 'bar' }

 * The testing framework specific files ('sinatra/test/spec',
   'sinatra/test/bacon', 'sinatra/test/rspec', etc.) have been deprecated.
   See http://sinatrarb.com/testing.html for instructions on setting up
   a testing environment with these frameworks.

 * The request-level #send_data method from Sinatra 0.3.3 has been added
   for compatibility but is deprecated.

 * Fix :provides causing crash on any request when request has no
   Accept header [#139]

 * Fix that ERB templates were evaluated twice per "erb" call.

 * Fix app-level middleware not being run when the Sinatra application is
   run as middleware.

 * Fixed some issues with running under Rack's CGI handler caused by
   writing informational stuff to stdout.

 * Fixed that reloading was sometimes enabled when starting from a
   rackup file [#110]

 * Fixed that "." in route patterns erroneously matched any character
   instead of a literal ".". [#124]

= 0.9.0.4 / 2009-01-25

 * Using halt with more than 1 args causes ArgumentError [#131]
 * using halt in a before filter doesn't modify response [#127]
 * Add deprecated Sinatra::EventContext to unbreak plugins [#130]
 * Give access to GET/POST params in filters [#129]
 * Preserve non-nested params in nested params hash [#117]
 * Fix backtrace dump with Rack::Lint [#116]

= 0.9.0.3 / 2009-01-21

 * Fall back on mongrel then webrick when thin not found. [#75]
 * Use :environment instead of :env in test helpers to
   fix deprecation warnings coming from framework.
 * Make sinatra/test/rspec work again [#113]
 * Fix app_file detection on windows [#118]
 * Fix static files with Rack::Lint in pipeline [#121]

= 0.9.0.2 / 2009-01-18

 * Halting a before block should stop processing of routes [#85]
 * Fix redirect/halt in before filters [#85]

= 0.9.0 / 2009-01-18

 * Works with and requires Rack >= 0.9.1

 * Multiple Sinatra applications can now co-exist peacefully within a
   single process. The new "Sinatra::Base" class can be subclassed to
   establish a blank-slate Rack application or middleware component.
   Documentation on using these features is forth-coming; the following
   provides the basic gist: http://gist.github.com/38605

 * Parameters with subscripts are now parsed into a nested/recursive
   Hash structure. e.g., "post[title]=Hello&post[body]=World" yields
   params: {'post' => {'title' => 'Hello', 'body' => 'World'}}.

 * Regular expressions may now be used in route pattens; captures are
   available at "params[:captures]".

 * New ":provides" route condition takes an array of mime types and
   matches only when an Accept request header is present with a
   corresponding type. [cypher]

 * New request-level "pass" method; immediately exits the current block
   and passes control to the next matching route.

 * The request-level "body" method now takes a block; evaluation is
   deferred until an attempt is made to read the body. The block must
   return a String or Array.

 * New "route conditions" system for attaching rules for when a route
   matches. The :agent and :host route options now use this system.

 * New "dump_errors" option controls whether the backtrace is dumped to
   rack.errors when an exception is raised from a route. The option is
   enabled by default for top-level apps.

 * Better default "app_file", "root", "public", and "views" location
   detection; changes to "root" and "app_file" automatically cascade to
   other options that depend on them.

 * Error mappings are now split into two distinct layers: exception
   mappings and custom error pages. Exception mappings are registered
   with "error(Exception)" and are run only when the app raises an
   exception. Custom error pages are registered with "error(status_code)",
   where "status_code" is an integer, and are run any time the response
   has the status code specified. It's also possible to register an error
   page for a range of status codes: "error(500..599)".

 * In-file templates are now automatically imported from the file that
   requires 'sinatra'. The use_in_file_templates! method is still available
   for loading templates from other files.

 * Sinatra's testing support is no longer dependent on Test::Unit. Requiring
   'sinatra/test' adds the Sinatra::Test module and Sinatra::TestHarness
   class, which can be used with any test framework. The 'sinatra/test/unit',
   'sinatra/test/spec', 'sinatra/test/rspec', or 'sinatra/test/bacon' files
   can be required to setup a framework-specific testing environment. See the
   README for more information.

 * Added support for Bacon (test framework). The 'sinatra/test/bacon' file
   can be required to setup Sinatra test helpers on Bacon::Context.

 * Deprecated "set_option" and "set_options"; use "set" instead.

 * Deprecated the "env" option ("options.env"); use "environment" instead.

 * Deprecated the request level "stop" method; use "halt" instead.

 * Deprecated the request level "entity_tag" method; use "etag" instead.
   Both "entity_tag" and "etag" were previously supported.

 * Deprecated the request level "headers" method (HTTP response headers);
   use "response['Header-Name']" instead.

 * Deprecated "Sinatra.application"; use "Sinatra::Application" instead.

 * Deprecated setting Sinatra.application = nil to reset an application.
   This should no longer be necessary.

 * Deprecated "Sinatra.default_options"; use
   "Sinatra::Default.set(key, value)" instead.

 * Deprecated the "ServerError" exception. All Exceptions are now
   treated as internal server errors and result in a 500 response
   status.

 * Deprecated the "get_it", "post_it", "put_it", "delete_it", and "head_it"
   test helper methods. Use "get", "post", "put", "delete", and "head",
   respectively, instead.

 * Removed Event and EventContext classes. Applications are defined in a
   subclass of Sinatra::Base; each request is processed within an
   instance.

= 0.3.3 / 2009-01-06

 * Pin to Rack 0.4.0 (this is the last release on Rack 0.4)

 * Log unhandled exception backtraces to rack.errors.

 * Use RACK_ENV environment variable to establish Sinatra
   environment when given. Thin sets this when started with
   the -e argument.

 * BUG: raising Sinatra::NotFound resulted in a 500 response
   code instead of 404.

 * BUG: use_in_file_templates! fails with CR/LF (#45)

 * BUG: Sinatra detects the app file and root path when run under
   thin/passenger.

= 0.3.2

 * BUG: Static and send_file read entire file into String before
   sending. Updated to stream with 8K chunks instead.

 * Rake tasks and assets for building basic documentation website.
   See http://sinatra.rubyforge.org

 * Various minor doc fixes.

= 0.3.1

 * Unbreak optional path parameters [jeremyevans]

= 0.3.0

 * Add sinatra.gemspec w/ support for github gem builds. Forks can now
   enable the build gem option in github to get free username-sinatra.gem
   builds: gem install username-sinatra.gem --source=http://gems.github.com/

 * Require rack-0.4 gem; removes frozen rack dir.

 * Basic RSpec support; require 'sinatra/test/rspec' instead of
   'sinatra/test/spec' to use. [avdi]

 * before filters can modify request environment vars used for
   routing (e.g., PATH_INFO, REQUEST_METHOD, etc.) for URL rewriting
   type functionality.

 * In-file templates now uses @@ instead of ## as template separator.

 * Top-level environment test predicates: development?, test?, production?

 * Top-level "set", "enable", and "disable" methods for tweaking
   app options. [rtomayko]

 * Top-level "use" method for building Rack middleware pipelines
   leading to app. See README for usage. [rtomayko]

 * New "reload" option - set false to disable reloading in development.

 * New "host" option - host/ip to bind to [cschneid]

 * New "app_file" option - override the file to reload in development
   mode [cschneid]

 * Development error/not_found page cleanup [sr, adamwiggins]

 * Remove a bunch of core extensions (String#to_param, String#from_param,
   Hash#from_params, Hash#to_params, Hash#symbolize_keys, Hash#pass)

 * Various grammar and formatting fixes to README; additions on
   community and contributing [cypher]

 * Build RDoc using Hanna template: http://sinatrarb.rubyforge.org/api

 * Specs, documentation and fixes for splat'n routes [vic]

 * Fix whitespace errors across all source files. [rtomayko]

 * Fix streaming issues with Mongrel (body not closed). [bmizerany]

 * Fix various issues with environment not being set properly (configure
   blocks not running, error pages not registering, etc.) [cypher]

 * Fix to allow locals to be passed to ERB templates [cschneid]

 * Fix locking issues causing random errors during reload in development.

 * Fix for escaped paths not resolving static files [Matthew Walker]

= 0.2.1

 * File upload fix and minor tweaks.

= 0.2.0

 * Initial gem release of 0.2 codebase.
