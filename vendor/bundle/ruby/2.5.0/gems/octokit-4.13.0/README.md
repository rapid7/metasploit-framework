# Octokit

Ruby toolkit for the GitHub API.

![logo](http://cl.ly/image/3Y013H0A2z3z/gundam-ruby.png)

Upgrading? Check the [Upgrade Guide](#upgrading-guide) before bumping to a new
[major version][semver].

## Table of Contents

1. [Philosophy](#philosophy)
2. [Quick start](#quick-start)
3. [Making requests](#making-requests)
4. [Consuming resources](#consuming-resources)
5. [Accessing HTTP responses](#accessing-http-responses)
6. [Authentication](#authentication)
   1. [Basic Authentication](#basic-authentication)
   2. [OAuth access tokens](#oauth-access-tokens)
   3. [Two-Factor Authentication](#two-factor-authentication)
   4. [Using a .netrc file](#using-a-netrc-file)
   5. [Application authentication](#application-authentication)
7. [Pagination](#pagination)
   1. [Auto pagination](#auto-pagination)
8. [Working with GitHub Enterprise](#working-with-github-enterprise)
   1. [Interacting with the GitHub.com APIs in GitHub Enterprise](#interacting-with-the-githubcom-apis-in-github-enterprise)
   2. [Interacting with the GitHub Enterprise Admin APIs](#interacting-with-the-github-enterprise-admin-apis)
   3. [Interacting with the GitHub Enterprise Management Console APIs](#interacting-with-the-github-enterprise-management-console-apis)
9. [SSL Connection Errors](#ssl-connection-errors)
10. [Configuration and defaults](#configuration-and-defaults)
    1. [Configuring module defaults](#configuring-module-defaults)
    2. [Using ENV variables](#using-env-variables)
11. [Hypermedia agent](#hypermedia-agent)
    1. [Hypermedia in Octokit](#hypermedia-in-octokit)
    2. [URI templates](#uri-templates)
    3. [The Full Hypermedia Experience™](#the-full-hypermedia-experience)
12. [Upgrading guide](#upgrading-guide)
    1. [Upgrading from 1.x.x](#upgrading-from-1xx)
13. [Advanced usage](#advanced-usage)
    1. [Debugging](#debugging)
    2. [Caching](#caching)
14. [Hacking on Octokit.rb](#hacking-on-octokitrb)
    1. [Running and writing new tests](#running-and-writing-new-tests)
15. [Supported Ruby Versions](#supported-ruby-versions)
16. [Versioning](#versioning)
17. [Making Repeating Requests](#making-repeating-requests)
18. [License](#license)

## Philosophy

API wrappers [should reflect the idioms of the language in which they were
written][wrappers]. Octokit.rb wraps the [GitHub API][github-api] in a flat API
client that follows Ruby conventions and requires little knowledge of REST.
Most methods have positional arguments for required input and an options hash
for optional parameters, headers, or other options:

```ruby
client = Octokit::Client.new

# Fetch a README with Accept header for HTML format
client.readme 'al3x/sovereign', :accept => 'application/vnd.github.html'
```

[wrappers]: http://wynnnetherland.com/journal/what-makes-a-good-api-wrapper
[github-api]: http://developer.github.com

## Quick start

Install via Rubygems

    gem install octokit

... or add to your Gemfile

    gem "octokit", "~> 4.0"

Access the library in Ruby:

    require 'octokit'

### Making requests

[API methods][] are available as client instance methods.

```ruby
# Provide authentication credentials
client = Octokit::Client.new(:login => 'defunkt', :password => 'c0d3b4ssssss!')

# Set access_token instead of login and password if you use personal access token
# client = Octokit::Client.new(:access_token => '[personal_access_token]!')

# Fetch the current user
client.user
```

### Additional Query Parameters

When passing additional parameters to GET based request use the following syntax:

```ruby
 # query: { parameter_name: 'value' }
 # Example: Get repository listing by owner in ascending order
 client.repos({}, query: {type: 'owner', sort: 'asc'})

 # Example: Get contents of a repository by ref
 # https://api.github.com/repos/octokit/octokit.rb/contents/path/to/file.rb?ref=some-other-branch
 client.contents('octokit/octokit.rb', path: 'path/to/file.rb', query: {ref: 'some-other-branch'})
```

[API methods]: http://octokit.github.io/octokit.rb/method_list.html

### Consuming resources

Most methods return a `Resource` object which provides dot notation and `[]`
access for fields returned in the API response.

```ruby
client = Octokit::Client.new

# Fetch a user
user = client.user 'jbarnette'
puts user.name
# => "John Barnette"
puts user.fields
# => <Set: {:login, :id, :gravatar_id, :type, :name, :company, :blog, :location, :email, :hireable, :bio, :public_repos, :followers, :following, :created_at, :updated_at, :public_gists}>
puts user[:company]
# => "GitHub"
user.rels[:gists].href
# => "https://api.github.com/users/jbarnette/gists"
```

**Note:** URL fields are culled into a separate `.rels` collection for easier
[Hypermedia](#hypermedia-agent) support.

### Accessing HTTP responses

While most methods return a `Resource` object or a Boolean, sometimes you may
need access to the raw HTTP response headers. You can access the last HTTP
response with `Client#last_response`:

```ruby
user      = client.user 'andrewpthorp'
response  = client.last_response
etag      = response.headers[:etag]
```

## Authentication

Octokit supports the various [authentication methods supported by the GitHub
API][auth]:

### Basic Authentication

Using your GitHub username and password is the easiest way to get started
making authenticated requests:

```ruby
client = Octokit::Client.new(:login => 'defunkt', :password => 'c0d3b4ssssss!')

user = client.user
user.login
# => "defunkt"
```
While Basic Authentication allows you to get started quickly, OAuth access
tokens are the preferred way to authenticate on behalf of users.

### OAuth access tokens

[OAuth access tokens][oauth] provide two main benefits over using your username
and password:

* **Revokable access**. Access tokens can be revoked, removing access for only
  that token without having to change your password everywhere.
* **Limited access**. Access tokens have [access scopes][] which allow for more
  granular access to API resources. For instance, you can grant a third party
  access to your gists but not your private repositories.

To use an access token with the Octokit client, pass your token in the
`:access_token` options parameter in lieu of your username and password:

```ruby
client = Octokit::Client.new(:access_token => "<your 40 char token>")

user = client.user
user.login
# => "defunkt"
```

You can [create access tokens through your GitHub Account Settings](https://help.github.com/articles/creating-an-access-token-for-command-line-use)
or with a basic authenticated Octokit client:

```ruby
client = Octokit::Client.new(:login => 'defunkt', :password => 'c0d3b4ssssss!')

client.create_authorization(:scopes => ["user"], :note => "Name of token")
# => <your new oauth token>
```

### Two-Factor Authentication

[Two-Factor Authentication](https://help.github.com/articles/about-two-factor-authentication) brings added security to the account by requiring more information to login.

Using two-factor authentication for API calls is as simple as adding the [required header](http://developer.github.com/v3/auth/#working-with-two-factor-authentication) as an option:

```ruby
client = Octokit::Client.new \
  :login    => 'defunkt',
  :password => 'c0d3b4ssssss!'

user = client.user("defunkt", :headers => { "X-GitHub-OTP" => "<your 2FA token>" })
```

As you can imagine, this gets annoying quick since two-factor auth tokens are very short lived. So it is recommended to create an oauth token for the user to communicate with the API:

```ruby
client = Octokit::Client.new \
  :login    => 'defunkt',
  :password => 'c0d3b4ssssss!'

client.create_authorization(:scopes => ["user"], :note => "Name of token",
                            :headers => { "X-GitHub-OTP" => "<your 2FA token>" })
# => <your new oauth token>
```

### Using a .netrc file

Octokit supports reading credentials from a netrc file (defaulting to
`~/.netrc`).  Given these lines in your netrc:

```
machine api.github.com
  login defunkt
  password c0d3b4ssssss!
```
You can now create a client with those credentials:

```ruby
client = Octokit::Client.new(:netrc => true)
client.login
# => "defunkt"
```
But _I want to use OAuth_ you say. Since the GitHub API supports using an OAuth
token as a Basic password, you totally can:

```
machine api.github.com
  login defunkt
  password <your 40 char token>
```

**Note:** Support for netrc requires adding the [netrc gem][] to your Gemfile
or `.gemspec`.

### Application authentication

Octokit also supports application-only authentication [using OAuth application client
credentials][app-creds]. Using application credentials will result in making
anonymous API calls on behalf of an application in order to take advantage of
the higher rate limit.

```ruby
client = Octokit::Client.new \
  :client_id     => "<your 20 char id>",
  :client_secret => "<your 40 char secret>"

user = client.user 'defunkt'
```

[auth]: http://developer.github.com/v3/#authentication
[oauth]: http://developer.github.com/v3/oauth/
[access scopes]: http://developer.github.com/v3/oauth/#scopes
[app-creds]: http://developer.github.com/v3/#increasing-the-unauthenticated-rate-limit-for-oauth-applications

## Default results per_page

Default results from the GitHub API are 30, if you wish to add more you must do so during Octokit configuration.

```ruby
Octokit::Client.new(access_token: "<your 40 char token>", per_page: 100)
```

## Pagination

Many GitHub API resources are [paginated][]. While you may be tempted to start
adding `:page` parameters to your calls, the API returns links to the next,
previous, and last pages for you in the `Link` response header as [Hypermedia
link relations](#hypermedia-agent).

```ruby
issues = client.issues 'rails/rails'
issues.concat client.last_response.rels[:next].get.data
```

### Auto pagination

For smallish resource lists, Octokit provides auto pagination. When this is
enabled, calls for paginated resources will fetch and concatenate the results
from every page into a single array:

```ruby
client.auto_paginate = true
issues = client.issues 'rails/rails'
issues.length

# => 702
```

You can also enable auto pagination for all Octokit client instances:

```ruby
Octokit.configure do |c|
  c.auto_paginate = true
end
```

**Note:** While Octokit auto pagination will set the page size to the maximum
`100`, and seek to not overstep your rate limit, you probably want to use a
custom pattern for traversing large lists.

[paginated]: http://developer.github.com/v3/#pagination

## Working with GitHub Enterprise

With a bit of setup, you can also use Octokit with your Github Enterprise instance.

### Interacting with the GitHub.com APIs in GitHub Enterprise

To interact with the "regular" GitHub.com APIs in GitHub Enterprise, simply configure the `api_endpoint` to match your hostname. For example:

``` ruby
Octokit.configure do |c|
  c.api_endpoint = "https://<hostname>/api/v3/"
end

client = Octokit::Client.new(:access_token => "<your 40 char token>")
```

### Interacting with the GitHub Enterprise Admin APIs

The GitHub Enterprise Admin APIs are under a different client: `EnterpriseAdminClient`. You'll need to have an administrator account in order to use these APIs.

``` ruby
admin_client = Octokit::EnterpriseAdminClient.new(
  :access_token => "<your 40 char token>",
  :api_endpoint => "https://<hostname>/api/v3/"
)

# or
Octokit.configure do |c|
  c.api_endpoint = "https://<hostname>/api/v3/"
  c.access_token = "<your 40 char token>"
end

admin_client = Octokit.enterprise_admin_client.new
```

### Interacting with the GitHub Enterprise Management Console APIs

The GitHub Enterprise Management Console APIs are also under a separate client: `EnterpriseManagementConsoleClient`. In order to use it, you'll need to provide both your management console password as well as the endpoint to your management console. This is different than the API endpoint provided above.

``` ruby
management_console_client = Octokit::EnterpriseManagementConsoleClient.new(
  :management_console_password => "secret",
  :management_console_endpoint = "https://hostname:8633"
)

# or
Octokit.configure do |c|
  c.management_console_endpoint = "https://hostname:8633"
  c.management_console_password = "secret"
end

management_console_client = Octokit.enterprise_management_console_client.new
```

### SSL Connection Errors

You *may* need to disable SSL temporarily while first setting up your GitHub Enterprise install. You can do that with the following configuration:

``` ruby
client.connection_options[:ssl] = { :verify => false }
```

Do remember to turn `:verify` back to `true`, as it's important for secure communication.

## Configuration and defaults

While `Octokit::Client` accepts a range of options when creating a new client
instance, Octokit's configuration API allows you to set your configuration
options at the module level. This is particularly handy if you're creating a
number of client instances based on some shared defaults. Changing options
affects new instances only and will not modify existing `Octokit::Client`
instances created with previous options.

### Configuring module defaults

Every writable attribute in {Octokit::Configurable} can be set one at a time:

```ruby
Octokit.api_endpoint = 'http://api.github.dev'
Octokit.web_endpoint = 'http://github.dev'
```

or in batch:

```ruby
Octokit.configure do |c|
  c.api_endpoint = 'http://api.github.dev'
  c.web_endpoint = 'http://github.dev'
end
```

### Using ENV variables

Default configuration values are specified in {Octokit::Default}. Many
attributes will look for a default value from the ENV before returning
Octokit's default.

```ruby
# Given $OCTOKIT_API_ENDPOINT is "http://api.github.dev"
client.api_endpoint

# => "http://api.github.dev"
```

Deprecation warnings and API endpoints in development preview warnings are
printed to STDOUT by default, these can be disabled by setting the ENV
`OCTOKIT_SILENT=true`.

## Hypermedia agent

Starting in version 2.0, Octokit is [hypermedia][]-enabled. Under the hood,
{Octokit::Client} uses [Sawyer][], a hypermedia client built on [Faraday][].

### Hypermedia in Octokit

Resources returned by Octokit methods contain not only data but hypermedia
link relations:

```ruby
user = client.user 'technoweenie'

# Get the repos rel, returned from the API
# as repos_url in the resource
user.rels[:repos].href
# => "https://api.github.com/users/technoweenie/repos"

repos = user.rels[:repos].get.data
repos.last.name
# => "faraday-zeromq"
```

When processing API responses, all `*_url` attributes are culled in to the link
relations collection. Any `url` attribute becomes `.rels[:self]`.

### URI templates

You might notice many link relations have variable placeholders. Octokit
supports [URI Templates][uri-templates] for parameterized URI expansion:

```ruby
repo = client.repo 'pengwynn/pingwynn'
rel = repo.rels[:issues]
# => #<Sawyer::Relation: issues: get https://api.github.com/repos/pengwynn/pingwynn/issues{/number}>

# Get a page of issues
rel.get.data

# Get issue #2
rel.get(:uri => {:number => 2}).data
```

### The Full Hypermedia Experience™

If you want to use Octokit as a pure hypermedia API client, you can start at
the API root and follow link relations from there:

```ruby
root = client.root
root.rels[:repository].get :uri => {:owner => "octokit", :repo => "octokit.rb" }
root.rels[:user_repositories].get :uri => { :user => "octokit" },
                                  :query => { :type => "owner" }
```

Octokit 3.0 aims to be hypermedia-driven, removing the internal URL
construction currently used throughout the client.

[hypermedia]: http://en.wikipedia.org/wiki/Hypermedia
[Sawyer]: https://github.com/lostisland/sawyer
[Faraday]: https://github.com/lostisland/faraday
[uri-templates]: http://tools.ietf.org/html/rfc6570

## Upgrading guide

Version 4.0

- **removes support for a [long-deprecated overload][list-pulls] for
passing state as a positional argument** when listing pull requests. Instead,
pass `state` in the method options.
- **drops support for Ruby < 2.0**.
- adds support for new [Enterprise-only APIs](#working-with-github-enterprise).
- adds support for [Repository redirects][redirects].

[list-pulls]: https://github.com/octokit/octokit.rb/commit/e48e91f736d5fce51e3bf74d7c9022aaa52f5c5c
[redirects]: https://developer.github.com/changes/2015-05-26-repository-redirects-are-coming/

Version 3.0 includes a couple breaking changes when upgrading from v2.x.x:

The [default media type][default-media-type] is now `v3` instead of `beta`. If
you need to request the older media type, you can set the default media type
for the client:

```ruby
Octokit.default_media_type = "application/vnd.github.beta+json"
```
or per-request

```ruby
client.emails(:accept => "application/vnd.github.beta+json")
```

The long-deprecated `Octokit::Client#create_download` method has been removed.

[default-media-type]: https://developer.github.com/changes/2014-01-07-upcoming-change-to-default-media-type/

### Upgrading from 1.x.x

Version 2.0 includes a completely rewritten `Client` factory that now memoizes
client instances based on unique configuration options. Breaking changes also
include:

* `:oauth_token` is now `:access_token`
* `:auto_traversal` is now `:auto_paginate`
* `Hashie::Mash` has been removed. Responses now return a `Sawyer::Resource`
  object. This new type behaves mostly like a Ruby `Hash`, but does not fully
  support the `Hashie::Mash` API.
* Two new client error types are raised where appropriate:
  `Octokit::TooManyRequests` and `Octokit::TooManyLoginAttempts`
* The `search_*` methods from v1.x are now found at `legacy_search_*`
* Support for netrc requires including the [netrc gem][] in your Gemfile or
  gemspec.
* DateTime fields are now proper `DateTime` objects. Previous versions outputted DateTime fields as 'String' objects.

[netrc gem]: https://rubygems.org/gems/netrc


## Advanced usage

Since Octokit employs [Faraday][faraday] under the hood, some behavior can be
extended via middleware.

### Debugging

Often, it helps to know what Octokit is doing under the hood. You can add a
logger to the middleware that enables you to peek into the underlying HTTP
traffic:

```ruby
stack = Faraday::RackBuilder.new do |builder|
  builder.use Faraday::Request::Retry, exceptions: [Octokit::ServerError]
  builder.use Octokit::Middleware::FollowRedirects
  builder.use Octokit::Response::RaiseError
  builder.use Octokit::Response::FeedParser
  builder.response :logger
  builder.adapter Faraday.default_adapter
end
Octokit.middleware = stack

client = Octokit::Client.new
client.user 'pengwynn'
```
```
I, [2013-08-22T15:54:38.583300 #88227]  INFO -- : get https://api.github.com/users/pengwynn
D, [2013-08-22T15:54:38.583401 #88227] DEBUG -- request: Accept: "application/vnd.github.beta+json"
User-Agent: "Octokit Ruby Gem 2.0.0.rc4"
I, [2013-08-22T15:54:38.843313 #88227]  INFO -- Status: 200
D, [2013-08-22T15:54:38.843459 #88227] DEBUG -- response: server: "GitHub.com"
date: "Thu, 22 Aug 2013 20:54:40 GMT"
content-type: "application/json; charset=utf-8"
transfer-encoding: "chunked"
connection: "close"
status: "200 OK"
x-ratelimit-limit: "60"
x-ratelimit-remaining: "39"
x-ratelimit-reset: "1377205443"
...
```

See the [Faraday README][faraday] for more middleware magic.

### Caching

If you want to boost performance, stretch your API rate limit, or avoid paying
the hypermedia tax, you can use [Faraday Http Cache][cache].

Add the gem to your Gemfile

    gem 'faraday-http-cache'

Next, construct your own Faraday middleware:

```ruby
stack = Faraday::RackBuilder.new do |builder|
  builder.use Faraday::HttpCache, serializer: Marshal, shared_cache: false
  builder.use Octokit::Response::RaiseError
  builder.adapter Faraday.default_adapter
end
Octokit.middleware = stack
```

Once configured, the middleware will store responses in cache based on ETag
fingerprint and serve those back up for future `304` responses for the same
resource. See the [project README][cache] for advanced usage.


[cache]: https://github.com/plataformatec/faraday-http-cache
[faraday]: https://github.com/lostisland/faraday

## Hacking on Octokit.rb

If you want to hack on Octokit locally, we try to make [bootstrapping the
project][bootstrapping] as painless as possible. To start hacking, clone and run:

    script/bootstrap

This will install project dependencies and get you up and running. If you want
to run a Ruby console to poke on Octokit, you can crank one up with:

    script/console

Using the scripts in `./scripts` instead of `bundle exec rspec`, `bundle
console`, etc.  ensures your dependencies are up-to-date.

### Running and writing new tests

Octokit uses [VCR][] for recording and playing back API fixtures during test
runs. These cassettes (fixtures) are part of the Git project in the `spec/cassettes`
folder. If you're not recording new cassettes you can run the specs with existing
cassettes with:

    script/test

Octokit uses environmental variables for storing credentials used in testing.
If you are testing an API endpoint that doesn't require authentication, you
can get away without any additional configuration. For the most part, tests
use an authenticated client, using a token stored in `ENV['OCTOKIT_TEST_GITHUB_TOKEN']`.
There are several different authenticating method's used across the api.
Here is the full list of configurable environmental variables for testing
Octokit:

ENV Variable | Description |
:-------------------|:-----------------|
`OCTOKIT_TEST_GITHUB_LOGIN`| GitHub login name (preferably one created specifically for testing against).
`OCTOKIT_TEST_GITHUB_PASSWORD`| Password for the test GitHub login.
`OCTOKIT_TEST_GITHUB_TOKEN` | [Personal Access Token](https://github.com/blog/1509-personal-api-tokens) for the test GitHub login.
`OCTOKIT_TEST_GITHUB_CLIENT_ID` | Test OAuth application client id.
`OCTOKIT_TEST_GITHUB_CLIENT_SECRET` | Test OAuth application client secret.
`OCTOKIT_TEST_GITHUB_REPOSITORY` | Test repository to perform destructive actions against, this should not be set to any repository of importance. **Automatically created by the test suite if nonexistent** Default: `api-sandbox`
`OCTOKIT_TEST_GITHUB_ORGANIZATION` | Test organization.
`OCTOKIT_TEST_GITHUB_ENTERPRISE_LOGIN` | GitHub Enterprise login name.
`OCTOKIT_TEST_GITHUB_ENTERPRISE_TOKEN` | GitHub Enterprise token.
`OCTOKIT_TEST_GITHUB_ENTERPRISE_MANAGEMENT_CONSOLE_PASSWORD` | GitHub Enterprise management console password.
`OCTOKIT_TEST_GITHUB_ENTERPRISE_ENDPOINT` | GitHub Enterprise hostname.
`OCTOKIT_TEST_GITHUB_ENTERPRISE_MANAGEMENT_CONSOLE_ENDPOINT` | GitHub Enterprise Management Console endpoint.
`OCTOKIT_TEST_GITHUB_INTEGRATION` | [GitHub Integration](https://developer.github.com/early-access/integrations/) owned by your test organization.
`OCTOKIT_TEST_GITHUB_INTEGRATION_INSTALLATION` | Installation of the GitHub Integration specified above.
`OCTOKIT_TEST_INTEGRATION_PEM_KEY` | File path to the private key generated from your integration.

Since we periodically refresh our cassettes, please keep some points in mind
when writing new specs.

* **Specs should be idempotent**. The HTTP calls made during a spec should be
  able to be run over and over. This means deleting a known resource prior to
  creating it if the name has to be unique.
* **Specs should be able to be run in random order.** If a spec depends on
  another resource as a fixture, make sure that's created in the scope of the
  spec and not depend on a previous spec to create the data needed.
* **Do not depend on authenticated user info.** Instead of asserting
  actual values in resources, try to assert the existence of a key or that a
  response is an Array. We're testing the client, not the API.

[bootstrapping]: http://wynnnetherland.com/linked/2013012801/bootstrapping-consistency
[VCR]: https://github.com/vcr/vcr

## Supported Ruby Versions

This library aims to support and is [tested against][travis] the following Ruby
implementations:

* Ruby 2.0
* Ruby 2.1
* Ruby 2.2
* Ruby 2.3
* Ruby 2.4
* Ruby 2.5

If something doesn't work on one of these Ruby versions, it's a bug.

This library may inadvertently work (or seem to work) on other Ruby
implementations, but support will only be provided for the versions listed
above.

If you would like this library to support another Ruby version, you may
volunteer to be a maintainer. Being a maintainer entails making sure all tests
run and pass on that implementation. When something breaks on your
implementation, you will be responsible for providing patches in a timely
fashion. If critical issues for a particular implementation exist at the time
of a major release, support for that Ruby version may be dropped.

[travis]: https://travis-ci.org/octokit/octokit.rb

## Versioning

This library aims to adhere to [Semantic Versioning 2.0.0][semver]. Violations
of this scheme should be reported as bugs. Specifically, if a minor or patch
version is released that breaks backward compatibility, that version should be
immediately yanked and/or a new version should be immediately released that
restores compatibility. Breaking changes to the public API will only be
introduced with new major versions. As a result of this policy, you can (and
should) specify a dependency on this gem using the [Pessimistic Version
Constraint][pvc] with two digits of precision. For example:

    spec.add_dependency 'octokit', '~> 3.0'

The changes made between versions can be seen on the [project releases page][releases].

[semver]: http://semver.org/
[pvc]: http://guides.rubygems.org/patterns/#pessimistic-version-constraint
[releases]: https://github.com/octokit/octokit.rb/releases

## Making Repeating Requests
In most cases it would be best to use a [webhooks](https://developer.github.com/webhooks/), but sometimes webhooks don't provide all of the information needed. In those cases where one might need to poll for progress or retry a request on failure, we designed [Octopoller](https://github.com/octokit/octopoller.rb). Octopoller is a micro gem perfect for making repeating requests. 

```ruby
Octopoller.poll(timeout: 15.seconds) do
  begin
    client.request_progress # ex. request a long running job's status
  rescue Error
    :re_poll
  end
end
```

This is useful when making requests for a long running job's progress (ex. requesting a [Source Import's progress](https://developer.github.com/v3/migrations/source_imports/#get-import-progress)).

## License

Copyright (c) 2009-2014 Wynn Netherland, Adam Stacoviak, Erik Michaels-Ober

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
