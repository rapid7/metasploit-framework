#MetasploitDataModels

The database layer for Metasploit


## Purpose
__MetasploitDataModels__ exists to do several key things:

1. Allow code sharing between Metasploit Framework (MSF) and the commercial versions of Metasploit (Community, Express, Pro -- usually referred to collectively as "Pro")

2. Give developers a lightweight entry point to MSF's backend for use in developing tools that gather data intended for later use with Metasploit (e.g. specialized scanners).

3. Make it easy to keep commercial stuff private while increasing the functionality of the open-source tools we provide to the community.


## Usage

### Rails

In a Rails application we simply include the ActiveRecord mixins directly, usually inside models with similar names.

### MSF
When MetasploitDataModels is included by MSF, the gem dynamically creates
ActiveRecord model classes.

Both of these behaviors are based on the assumption that the files in
__lib/metasploit_data_models/active_record_models__, though implemented here as
mixins, actually represent the basic ActiveRecord model structure that both Metasploit Framework and Metasploit Pro use.

### Elsewhere

__NOTE: This isn't in RubyGems yet.  Using a Gemfile entry pointing to this repo (i.e., using [Bundler](http://gembundler.com)) is the suggested option for now.__


Usage outside of Rapid7 is still alpha, and we're not making many promises.  That being said, usage is easy:

```ruby
connection_info = YAML.load_file("path/to/rails-style/db_config_file")
ActiveRecord::Base.establish_connection(connection_info['development'])
include MetasploitDataModels
MetasploitDataModels.create_and_load_ar_classes
```

Basically you need to do the following things:

1. Establish an ActiveRecord connection.  A Rails __config/database.yml__ is ideal for this.
2. Include the MetasploitDataModels module.
3. Call the class method that builds the AR models into the Mdm namespace( __MetasploitDataModels.create_and_load_ar_classes__ ).


## Developer Info

### Console
The gem includes a console based on [Pry](https://github.com/pry/pry/)

Give it a path to a working MSF database.yml file for full
ActiveRecord-based access to your data.

__Note:__ "development" mode is hardcoded into the console currently.

### ActiveRecord::ConnectionError issues
Because the gem is defining mixins, there can be no knowledge of the
specifics of any "current" ActiveRecord connection.  But if ActiveRecord
encounters something in a child class that would require knowledge of
the connection adapter (e.g. the use of an RDBMS-specific function in
a named scope's "WHERE" clause), it will check to see if the adapter
supports it and then throw an exception when the connection object
(which provides the adapter) is nil.

This means that, for all but the most trivial cases, you need to use Arel 
versions of queries instead of ones utilizing straight SQL.

You'll encounter this sometimes if you do dev work on this gem.  A good
rule of thumb: anything that goes into the class_eval block must be able
to work without knowledge of the AR connection adapter type.
