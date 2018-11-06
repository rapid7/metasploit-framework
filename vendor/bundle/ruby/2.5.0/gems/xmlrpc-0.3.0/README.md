# XMLRPC

[![Build Status](https://travis-ci.org/ruby/xmlrpc.svg?branch=master)](https://travis-ci.org/ruby/xmlrpc)

## Overview

XMLRPC is a lightweight protocol that enables remote procedure calls over
HTTP.  It is defined at http://www.xmlrpc.com.

XMLRPC allows you to create simple distributed computing solutions that span
computer languages.  Its distinctive feature is its simplicity compared to
other approaches like SOAP and CORBA.

The Ruby standard library package 'xmlrpc' enables you to create a server that
implements remote procedures and a client that calls them.  Very little code
is required to achieve either of these.

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'xmlrpc'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install xmlrpc

## Example

Try the following code.  It calls a standard demonstration remote procedure.

```ruby
require 'xmlrpc/client'
require 'pp'

server = XMLRPC::Client.new2("http://xmlrpc-c.sourceforge.net/api/sample.php")
result = server.call("sample.sumAndDifference", 5, 3)
pp result
```

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/ruby/xmlrpc.


## License

Released under the same term of license as Ruby.
