# Metasploit::Credential [![Build Status](https://travis-ci.org/rapid7/metasploit-credential.svg?branch=master)](https://travis-ci.org/rapid7/metasploit-credential)[![Code Climate](https://codeclimate.com/github/rapid7/metasploit-credential.png)](https://codeclimate.com/github/rapid7/metasploit-credential)[![Dependency Status](https://gemnasium.com/rapid7/metasploit-credential.svg)](https://gemnasium.com/rapid7/metasploit-credential)[![Gem Version](https://badge.fury.io/rb/metasploit-credential.svg)](http://badge.fury.io/rb/metasploit-credential)[![Inline docs](http://inch-ci.org/github/rapid7/metasploit-credential.svg)](http://inch-ci.org/github/rapid7/metasploit-credential)[![PullReview stats](https://www.pullreview.com/github/rapid7/metasploit-credential/badges/master.svg)](https://www.pullreview.com/github/rapid7/metasploit-credential/reviews/master)

## Versioning

`Metasploit::Credential` is versioned using [semantic versioning 2.0](http://semver.org/spec/v2.0.0.html).  Each branch
should set `Metasploit::Credential::Version::PRERELEASE` to the branch name, while master should have no `PRERELEASE`
and the `PRERELEASE` section of `Metasploit::Credential::VERSION` does not exist.

## Documentation

`Metasploit::Credential` is documented using YARD.  For each `ActiveRecord::Base` descendant, it uses `RailsERD` to
generate an Entity-Relationship Diagram of all classes to which the descendant has a `belongs_to` relationship either
directly or indirectly.

### Database Setup

`RailsERD` requires access to the database to walk the `ActiveRecord::Base` associations, so setup the `database.yml`,
create the database, and run the migrations:

    cp spec/dummy/config/database.yml.example spec/dummy/config/database.yml
    # fill in passwords
    edit spec/dummy/config/database.yml
    rake db:create db:migrate
    
### Graphviz Setup

In order to generate the diagrams as PNGs, graphviz is used.  It will need to be installed using your OS's package
manager.

#### OSX

    `brew install graphviz`

Graphviz may have issues when used on OSX Mavericks or later.  If `rake yard` hangs or you get
`'CoreTest performance note'` messages when running 'rake yard', you should reinstall graphviz as follows:
`brew reinstall graphviz --with-bindings --with-freetype --with-librsvg --with-pangocairo`.

### Generate

   rake yard
   
### Reading

   open doc/frames.html
   
#### ERDs

To view the ERDs, which you can't see on [rubydoc.info](http://rubydoc.info/gems/metasploit-credential), you can look
at the docs for `Metasploit::Credential`

   open doc/Metasploit/Credential.html

## Installation

Add this line to your application's `Gemfile`:

    gem 'metasploit-credential'

And then execute:

    $ bundle
    
**This gem's `Rails::Engine` is not required automatically.** You'll need to also add the following to your `config/application.rb`:

    require 'metasploit/credential/engine'

Or install it yourself as:

    $ gem install metasploit-credential

### `Net::SSH`

`Metasploit::Credential::SSHKey` depends on `'net/ssh'`, but `metasploit-credential` does not declare the `net-ssh` gem
as a runtime dependency because [`metasploit-framework`](https://github.com/rapid7/metasploit-framework) includes
[its own version of `'net/ssh'`](https://github.com/rapid7/metasploit-framework/blob/master/lib/net/ssh.rb) which would
conflict with the gem.

If you're not using `metasploit-framework`, then you need add the `net-ssh` to your `Gemfile`:

    gem 'net-ssh'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install net-ssh

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## Testing

`Metasploit::Credential` is tested using [RSpec](https://github.com/rspec/rspec)

### Dependencies

Remove your `Gemfile.lock` so you test with the latest compatible dependencies as will be done on
[travis-ci](https://travis-ci.org/rapid7/metasploit-credential)

    rm Gemfile.lock
    bundle install

### Database Setup

To run the specs, access to the database is required, so setup the `database.yml`, create the database, and run the
migrations:

    cp spec/dummy/config/database.yml.example spec/dummy/config/database.yml
    # fill in passwords
    edit spec/dummy/config/database.yml
    rake db:create db:migrate

### Running

    rake spec
