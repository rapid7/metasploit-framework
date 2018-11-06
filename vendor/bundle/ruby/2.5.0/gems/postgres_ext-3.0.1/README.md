# PostgresExt

## You can help!
This gem could use some updating, and I've moved on from Ruby, but I'd like to see this gem continue to survive. If you're interested in helping maintain the gem, please reach out on [twitter](https://twitter.com/_danmcclain).

## Overview

Adds missing native PostgreSQL data types to ActiveRecord and convenient querying extensions for ActiveRecord and Arel for Rails 4.x

[![Build Status](https://secure.travis-ci.org/danmcclain/postgres_ext.png?branch=master)](https://travis-ci.org/danmcclain/postgres_ext)
[![Code Climate](https://codeclimate.com/github/danmcclain/postgres_ext.png)](https://codeclimate.com/github/danmcclain/postgres_ext)
[![Gem Version](https://badge.fury.io/rb/postgres_ext.png)](https://badge.fury.io/rb/postgres_ext)

## Looking for help? ##

Bug or question?  [Please open an issue on
Github](https://github.com/danmcclain/postgres_ext/issues).
## Installation

Add this line to your application's Gemfile:

    gem 'postgres_ext'

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install postgres_ext

## Usage

Just `require 'postgres_ext'` and use ActiveRecord as you normally would! postgres\_ext extends
ActiveRecord's data type handling and query methods in both Arel and
ActiveRecord.

 * [Querying PostgreSQL datatypes](docs/querying.md)

Where are the datatypes from PostgresExt 1.x? ActiveRecord 4.x includes
all the data types that PostgresExt added to ActiveRecord 3.2.x. We'll
be adding more datatypes as we come across them.

## Developing

To work on postgres\_ext locally, follow these steps:

 1. Run `bundle install`, this will install (almost) all the development
    dependencies
 2. Run `gem install byebug` (not a declared dependency to not break CI)
 3. Run `bundle exec rake db:setup`, this will set up the `.env` file necessary to run
    the tests and set up the database
 4. Run `bundle exec rake db:create`, this will create the test database
 5. Run `bundle exec rake db:migrate`, this will set up the database tables required
    by the test
 6. Run `BUNDLE_GEMFILE='gemfiles/Gemfile.activerecord-4.0.x' bundle install --quiet` to create the Gemfile.lock for 4.0.
 7. Run `BUNDLE_GEMFILE='gemfiles/Gemfile.activerecord-4.1.x' bundle install --quiet` to create the Gemfile.lock for 4.1.
 8. Run `bundle exec rake test:all` to run tests against all supported versions of Active Record

## Authors

Dan McClain [twitter](http://twitter.com/_danmcclain) [github](http://github.com/danmcclain)

