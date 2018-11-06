Sun Dec 4 18:48:03 2015  Jeremy Daer <jeremydaer@gmail.com>

	* First-party "SameSite" cookies. Browsers omit SameSite cookies
	from third-party requests, closing the door on many CSRF attacks.

	Pass `same_site: true` (or `:strict`) to enable:
	    response.set_cookie 'foo', value: 'bar', same_site: true
	or `same_site: :lax` to use Lax enforcement:
	    response.set_cookie 'foo', value: 'bar', same_site: :lax

	Based on version 7 of the Same-site Cookies internet draft:
	https://tools.ietf.org/html/draft-west-first-party-cookies-07

	Thanks to Ben Toews (@mastahyeti) and Bob Long (@bobjflong) for
	updating to drafts 5 and 7.

Wed Jun 24 12:13:37 2015  Aaron Patterson <tenderlove@ruby-lang.org>

	* Fix Ruby 1.8 backwards compatibility

Fri Jun 19 07:14:50 2015  Matthew Draper <matthew@trebex.net>

	* Work around a Rails incompatibility in our private API

Fri Jun 12 11:37:41 2015  Aaron Patterson <tenderlove@ruby-lang.org>

	* Prevent extremely deep parameters from being parsed. CVE-2015-3225

### December 18th, Thirty sixth public release 1.6.0

### February 7th, Thirty fifth public release 1.5.2
  - Fix CVE-2013-0263, timing attack against Rack::Session::Cookie
  - Fix CVE-2013-0262, symlink path traversal in Rack::File
  - Add various methods to Session for enhanced Rails compatibility
  - Request#trusted_proxy? now only matches whole stirngs
  - Add JSON cookie coder, to be default in Rack 1.6+ due to security concerns
  - URLMap host matching in environments that don't set the Host header fixed
  - Fix a race condition that could result in overwritten pidfiles
  - Various documentation additions

### February 7th, Thirty fifth public release 1.4.5
  - Fix CVE-2013-0263, timing attack against Rack::Session::Cookie
  - Fix CVE-2013-0262, symlink path traversal in Rack::File

### February 7th, Thirty fifth public release 1.1.6, 1.2.8, 1.3.10
  - Fix CVE-2013-0263, timing attack against Rack::Session::Cookie

### January 28th, 2013: Thirty fourth public release 1.5.1
  - Rack::Lint check_hijack now conforms to other parts of SPEC
  - Added hash-like methods to Abstract::ID::SessionHash for compatibility
  - Various documentation corrections

### January 21st, 2013: Thirty third public release 1.5.0
  - Introduced hijack SPEC, for before-response and after-response hijacking
  - SessionHash is no longer a Hash subclass
  - Rack::File cache_control parameter is removed, in place of headers options
  - Rack::Auth::AbstractRequest#scheme now yields strings, not symbols
  - Rack::Utils cookie functions now format expires in RFC 2822 format
  - Rack::File now has a default mime type
  - rackup -b 'run Rack::File.new(".")', option provides command line configs
  - Rack::Deflater will no longer double encode bodies
  - Rack::Mime#match? provides convenience for Accept header matching
  - Rack::Utils#q_values provides splitting for Accept headers
  - Rack::Utils#best_q_match provides a helper for Accept headers
  - Rack::Handler.pick provides convenience for finding available servers
  - Puma added to the list of default servers (preferred over Webrick)
  - Various middleware now correctly close body when replacing it
  - Rack::Request#params is no longer persistent with only GET params
  - Rack::Request#update_param and #delete_param provide persistent operations
  - Rack::Request#trusted_proxy? now returns true for local unix sockets
  - Rack::Response no longer forces Content-Types
  - Rack::Sendfile provides local mapping configuration options
  - Rack::Utils#rfc2109 provides old netscape style time output
  - Updated HTTP status codes
  - Ruby 1.8.6 likely no longer passes tests, and is no longer fully supported

### January 13th, 2013: Thirty second public release 1.4.4, 1.3.9, 1.2.7, 1.1.5
  - [SEC] Rack::Auth::AbstractRequest no longer symbolizes arbitrary strings
  - Fixed erroneous test case in the 1.3.x series

### January 7th, 2013: Thirty first public release 1.4.3
  - Security: Prevent unbounded reads in large multipart boundaries

### January 7th, 2013: Thirtieth public release 1.3.8
  - Security: Prevent unbounded reads in large multipart boundaries

### January 6th, 2013: Twenty ninth public release 1.4.2
  - Add warnings when users do not provide a session secret
  - Fix parsing performance for unquoted filenames
  - Updated URI backports
  - Fix URI backport version matching, and silence constant warnings
  - Correct parameter parsing with empty values
  - Correct rackup '-I' flag, to allow multiple uses
  - Correct rackup pidfile handling
  - Report rackup line numbers correctly
  - Fix request loops caused by non-stale nonces with time limits
  - Fix reloader on Windows
  - Prevent infinite recursions from Response#to_ary
  - Various middleware better conforms to the body close specification
  - Updated language for the body close specification
  - Additional notes regarding ECMA escape compatibility issues
  - Fix the parsing of multiple ranges in range headers
  - Prevent errors from empty parameter keys
  - Added PATCH verb to Rack::Request
  - Various documentation updates
  - Fix session merge semantics (fixes rack-test)
  - Rack::Static :index can now handle multiple directories
  - All tests now utilize Rack::Lint (special thanks to Lars Gierth)
  - Rack::File cache_control parameter is now deprecated, and removed by 1.5
  - Correct Rack::Directory script name escaping
  - Rack::Static supports header rules for sophisticated configurations
  - Multipart parsing now works without a Content-Length header
  - New logos courtesy of Zachary Scott!
  - Rack::BodyProxy now explicitly defines #each, useful for C extensions
  - Cookies that are not URI escaped no longer cause exceptions

### January 6th, 2013: Twenty eighth public release 1.3.7
  - Add warnings when users do not provide a session secret
  - Fix parsing performance for unquoted filenames
  - Updated URI backports
  - Fix URI backport version matching, and silence constant warnings
  - Correct parameter parsing with empty values
  - Correct rackup '-I' flag, to allow multiple uses
  - Correct rackup pidfile handling
  - Report rackup line numbers correctly
  - Fix request loops caused by non-stale nonces with time limits
  - Fix reloader on Windows
  - Prevent infinite recursions from Response#to_ary
  - Various middleware better conforms to the body close specification
  - Updated language for the body close specification
  - Additional notes regarding ECMA escape compatibility issues
  - Fix the parsing of multiple ranges in range headers

### January 6th, 2013: Twenty seventh public release 1.2.6
  - Add warnings when users do not provide a session secret
  - Fix parsing performance for unquoted filenames

### January 6th, 2013: Twenty sixth public release 1.1.4
  - Add warnings when users do not provide a session secret

### January 22nd, 2012: Twenty fifth public release 1.4.1
  - Alter the keyspace limit calculations to reduce issues with nested params
  - Add a workaround for multipart parsing where files contain unescaped "%"
  - Added Rack::Response::Helpers#method_not_allowed? (code 405)
  - Rack::File now returns 404 for illegal directory traversals
  - Rack::File now returns 405 for illegal methods (non HEAD/GET)
  - Rack::Cascade now catches 405 by default, as well as 404
  - Cookies missing '--' no longer cause an exception to be raised
  - Various style changes and documentation spelling errors
  - Rack::BodyProxy always ensures to execute its block
  - Additional test coverage around cookies and secrets
  - Rack::Session::Cookie can now be supplied either secret or old_secret
  - Tests are no longer dependent on set order
  - Rack::Static no longer defaults to serving index files
  - Rack.release was fixed

### December 28th, 2011: Twenty fourth public release 1.4.0
  - Ruby 1.8.6 support has officially been dropped. Not all tests pass.
  - Raise sane error messages for broken config.ru
  - Allow combining run and map in a config.ru
  - Rack::ContentType will not set Content-Type for responses without a body
  - Status code 205 does not send a response body
  - Rack::Response::Helpers will not rely on instance variables
  - Rack::Utils.build_query no longer outputs '=' for nil query values
  - Various mime types added
  - Rack::MockRequest now supports HEAD
  - Rack::Directory now supports files that contain RFC3986 reserved chars
  - Rack::File now only supports GET and HEAD requests
  - Rack::Server#start now passes the block to Rack::Handler::<h>#run
  - Rack::Static now supports an index option
  - Added the Teapot status code
  - rackup now defaults to Thin instead of Mongrel (if installed)
  - Support added for HTTP_X_FORWARDED_SCHEME
  - Numerous bug fixes, including many fixes for new and alternate rubies

### December 28th, 2011: Twenty first public release: 1.1.3.
  - Security fix. http://www.ocert.org/advisories/ocert-2011-003.html
    Further information here: http://jruby.org/2011/12/27/jruby-1-6-5-1

### October 17, 2011: Twentieth public release 1.3.5
  - Fix annoying warnings caused by the backport in 1.3.4

### October 1, 2011: Nineteenth public release 1.3.4
  - Backport security fix from 1.9.3, also fixes some roundtrip issues in URI
  - Small documentation update
  - Fix an issue where BodyProxy could cause an infinite recursion
  - Add some supporting files for travis-ci

### September 16, 2011: Eighteenth public release 1.2.4
  - Fix a bug with MRI regex engine to prevent XSS by malformed unicode

### September 16, 2011: Seventeenth public release 1.3.3
  - Fix bug with broken query parameters in Rack::ShowExceptions
  - Rack::Request#cookies no longer swallows exceptions on broken input
  - Prevents XSS attacks enabled by bug in Ruby 1.8's regexp engine
  - Rack::ConditionalGet handles broken If-Modified-Since helpers

### July 16, 2011: Sixteenth public release 1.3.2
  - Fix for Rails and rack-test, Rack::Utils#escape calls to_s

### July 13, 2011: Fifteenth public release 1.3.1
  - Fix 1.9.1 support
  - Fix JRuby support
  - Properly handle $KCODE in Rack::Utils.escape
  - Make method_missing/respond_to behavior consistent for Rack::Lock,
    Rack::Auth::Digest::Request and Rack::Multipart::UploadedFile
  - Reenable passing rack.session to session middleware
  - Rack::CommonLogger handles streaming responses correctly
  - Rack::MockResponse calls close on the body object
  - Fix a DOS vector from MRI stdlib backport

### May 22nd, 2011: Fourteenth public release 1.2.3
  - Pulled in relevant bug fixes from 1.3
  - Fixed 1.8.6 support

### May 22nd, 2011: Thirteenth public release 1.3.0
  - Various performance optimizations
  - Various multipart fixes
  - Various multipart refactors
  - Infinite loop fix for multipart
  - Test coverage for Rack::Server returns
  - Allow files with '..', but not path components that are '..'
  - rackup accepts handler-specific options on the command line
  - Request#params no longer merges POST into GET (but returns the same)
  - Use URI.encode_www_form_component instead. Use core methods for escaping.
  - Allow multi-line comments in the config file
  - Bug L#94 reported by Nikolai Lugovoi, query parameter unescaping.
  - Rack::Response now deletes Content-Length when appropriate
  - Rack::Deflater now supports streaming
  - Improved Rack::Handler loading and searching
  - Support for the PATCH verb
  - env['rack.session.options'] now contains session options
  - Cookies respect renew
  - Session middleware uses SecureRandom.hex

### March 13th, 2011: Twelfth public release 1.2.2/1.1.2.
  - Security fix in Rack::Auth::Digest::MD5: when authenticator
    returned nil, permission was granted on empty password.

### June 15th, 2010: Eleventh public release 1.2.1.
  - Make CGI handler rewindable
  - Rename spec/ to test/ to not conflict with SPEC on lesser
    operating systems

### June 13th, 2010: Tenth public release 1.2.0.
  - Removed Camping adapter: Camping 2.0 supports Rack as-is
  - Removed parsing of quoted values
  - Add Request.trace? and Request.options?
  - Add mime-type for .webm and .htc
  - Fix HTTP_X_FORWARDED_FOR
  - Various multipart fixes
  - Switch test suite to bacon

### January 3rd, 2010: Ninth public release 1.1.0.
  - Moved Auth::OpenID to rack-contrib.
  - SPEC change that relaxes Lint slightly to allow subclasses of the
    required types
  - SPEC change to document rack.input binary mode in greator detail
  - SPEC define optional rack.logger specification
  - File servers support X-Cascade header
  - Imported Config middleware
  - Imported ETag middleware
  - Imported Runtime middleware
  - Imported Sendfile middleware
  - New Logger and NullLogger middlewares
  - Added mime type for .ogv and .manifest.
  - Don't squeeze PATH_INFO slashes
  - Use Content-Type to determine POST params parsing
  - Update Rack::Utils::HTTP_STATUS_CODES hash
  - Add status code lookup utility
  - Response should call #to_i on the status
  - Add Request#user_agent
  - Request#host knows about forwared host
  - Return an empty string for Request#host if HTTP_HOST and
    SERVER_NAME are both missing
  - Allow MockRequest to accept hash params
  - Optimizations to HeaderHash
  - Refactored rackup into Rack::Server
  - Added Utils.build_nested_query to complement Utils.parse_nested_query
  - Added Utils::Multipart.build_multipart to complement
    Utils::Multipart.parse_multipart
  - Extracted set and delete cookie helpers into Utils so they can be
    used outside Response
  - Extract parse_query and parse_multipart in Request so subclasses
    can change their behavior
  - Enforce binary encoding in RewindableInput
  - Set correct external_encoding for handlers that don't use RewindableInput

### October 18th, 2009: Eighth public release 1.0.1.
  - Bump remainder of rack.versions.
  - Support the pure Ruby FCGI implementation.
  - Fix for form names containing "=": split first then unescape components
  - Fixes the handling of the filename parameter with semicolons in names.
  - Add anchor to nested params parsing regexp to prevent stack overflows
  - Use more compatible gzip write api instead of "<<".
  - Make sure that Reloader doesn't break when executed via ruby -e
  - Make sure WEBrick respects the :Host option
  - Many Ruby 1.9 fixes.

### April 25th, 2009: Seventh public release 1.0.0.
  - SPEC change: Rack::VERSION has been pushed to [1,0].
  - SPEC change: header values must be Strings now, split on "\n".
  - SPEC change: Content-Length can be missing, in this case chunked transfer
    encoding is used.
  - SPEC change: rack.input must be rewindable and support reading into
    a buffer, wrap with Rack::RewindableInput if it isn't.
  - SPEC change: rack.session is now specified.
  - SPEC change: Bodies can now additionally respond to #to_path with
    a filename to be served.
  - NOTE: String bodies break in 1.9, use an Array consisting of a
    single String instead.
  - New middleware Rack::Lock.
  - New middleware Rack::ContentType.
  - Rack::Reloader has been rewritten.
  - Major update to Rack::Auth::OpenID.
  - Support for nested parameter parsing in Rack::Response.
  - Support for redirects in Rack::Response.
  - HttpOnly cookie support in Rack::Response.
  - The Rakefile has been rewritten.
  - Many bugfixes and small improvements.

### January 9th, 2009: Sixth public release 0.9.1.
  - Fix directory traversal exploits in Rack::File and Rack::Directory.

### January 6th, 2009: Fifth public release 0.9.
  - Rack is now managed by the Rack Core Team.
  - Rack::Lint is stricter and follows the HTTP RFCs more closely.
  - Added ConditionalGet middleware.
  - Added ContentLength middleware.
  - Added Deflater middleware.
  - Added Head middleware.
  - Added MethodOverride middleware.
  - Rack::Mime now provides popular MIME-types and their extension.
  - Mongrel Header now streams.
  - Added Thin handler.
  - Official support for swiftiplied Mongrel.
  - Secure cookies.
  - Made HeaderHash case-preserving.
  - Many bugfixes and small improvements.

### August 21st, 2008: Fourth public release 0.4.
  - New middleware, Rack::Deflater, by Christoffer Sawicki.
  - OpenID authentication now needs ruby-openid 2.
  - New Memcache sessions, by blink.
  - Explicit EventedMongrel handler, by Joshua Peek <josh@joshpeek.com>
  - Rack::Reloader is not loaded in rackup development mode.
  - rackup can daemonize with -D.
  - Many bugfixes, especially for pool sessions, URLMap, thread safety
    and tempfile handling.
  - Improved tests.
  - Rack moved to Git.

### February 26th, 2008: Third public release 0.3.
  - LiteSpeed handler, by Adrian Madrid.
  - SCGI handler, by Jeremy Evans.
  - Pool sessions, by blink.
  - OpenID authentication, by blink.
  - :Port and :File options for opening FastCGI sockets, by blink.
  - Last-Modified HTTP header for Rack::File, by blink.
  - Rack::Builder#use now accepts blocks, by Corey Jewett.
    (See example/protectedlobster.ru)
  - HTTP status 201 can contain a Content-Type and a body now.
  - Many bugfixes, especially related to Cookie handling.

### May 16th, 2007: Second public release 0.2.
  - HTTP Basic authentication.
  - Cookie Sessions.
  - Static file handler.
  - Improved Rack::Request.
  - Improved Rack::Response.
  - Added Rack::ShowStatus, for better default error messages.
  - Bug fixes in the Camping adapter.
  - Removed Rails adapter, was too alpha.

### March 3rd, 2007: First public release 0.1.
