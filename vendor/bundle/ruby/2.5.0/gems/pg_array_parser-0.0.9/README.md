# PgArrayParser
[![Build Status](http://travis-ci.org/dockyard/easy_auth.png)](http://travis-ci.org/dockyard/pg_array_parser)
[![Code Climate](https://codeclimate.com/badge.png)](https://codeclimate.com/github/dockyard/pg_array_parser)

Fast PostreSQL array parsing.
## Installation

Add this line to your application's Gemfile:

```ruby
gem 'pg_array_parser'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install pg_array_parser

## Usage

Include the `PgArrayParser` module, which provides the `parse_pg_array`
method.

```ruby
class MyPostgresParser
  include PgArrayParser
end

parser = MyPostgresParser.new
parser.parse_pg_array '{}'
# => []
parser.parse_pg_array '{1,2,3,4}'
# => ["1", "2", "3", "4"]
parser.parse_pg_array '{1,{2,3},4}'
# => ["1", ["2", "3"], "4"]
parser.parse_pg_array '{some,strings that,"May have some ,\'s"}'
# => ["some", "strings that", "May have some ,'s"]
```

## Authors

[Dan McClain](http://github.com/danmcclain) [twitter](http://twitter.com/_danmcclain) 

## Versioning ##

This gem follows [Semantic Versioning](http://semver.org)

## Want to help? ##

Stable branches are created based upon each minor version. Please make
pull requests to specific branches rather than master.

Please make sure you include tests!

Unles Rails drops support for Ruby 1.8.7 we will continue to use the
hash-rocket syntax. Please respect this.

Don't use tabs to indent, two spaces are the standard.

## Legal ##

[DockYard](http://dockyard.com), LLC &copy; 2012

[@dockyard](http://twitter.com/dockyard)

[Licensed under the MIT
license](http://www.opensource.org/licenses/mit-license.php)
