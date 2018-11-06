[![Build Status](https://travis-ci.org/kost/nessus_rest-ruby.png)](https://travis-ci.org/kost/nessus_rest-ruby)
[![Coverage Status](https://coveralls.io/repos/kost/nessus_rest-ruby/badge.png?branch=master)](https://coveralls.io/r/kost/nessus_rest-ruby?branch=master)

# nessus_rest

Communicate with Nessus Scanner (version 6+) over REST/JSON interface

## Usage

```ruby
require 'nessus_rest'

n=NessusREST::Client.new ({
	:url=>'https://localhost:8834', 
	:username=>'user',
	:password=> 'password' })
qs=n.scan_quick_template('basic','name-of-scan','localhost')
scanid=qs['scan']['id']
n.scan_wait4finish(scanid)
n.report_download_file(scanid,'csv','myscanreport.csv')
```

## Installation

Add this line to your application's Gemfile:

    gem 'nessus_rest'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install nessus_rest

## Requirements

Requirements are quite standard Ruby libraries for HTTPS and JSON
parsing:
```ruby
require 'uri'
require 'net/https'
require 'json'
```

## Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request

### Todo
- [ ] Provide more examples

## Copyright
Copyright (c) 2016 Vlatko Kosturjak. See LICENSE.txt for
further details.

## Credits

Vlatko Kosturjak made initial Nessus XMLRPC library. Averagesecurityguy made
initial JSON REST patches. Vlatko did bugfixes, gemification and few features.

