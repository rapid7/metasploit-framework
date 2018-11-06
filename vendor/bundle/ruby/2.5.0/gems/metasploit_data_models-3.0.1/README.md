#MetasploitDataModels [![Build Status](https://travis-ci.org/rapid7/metasploit_data_models.png)](https://travis-ci.org/rapid7/metasploit_data_models)[![Code Climate](https://codeclimate.com/github/rapid7/metasploit_data_models.png)](https://codeclimate.com/github/rapid7/metasploit_data_models)[![Coverage Status](https://coveralls.io/repos/rapid7/metasploit_data_models/badge.png)](https://coveralls.io/r/rapid7/metasploit_data_models)[![Dependency Status](https://gemnasium.com/rapid7/metasploit_data_models.png)](https://gemnasium.com/rapid7/metasploit_data_models)[![Gem Version](https://badge.fury.io/rb/metasploit_data_models.png)](http://badge.fury.io/rb/metasploit_data_models)

The database layer for Metasploit


## Purpose
__MetasploitDataModels__ exists to do several key things:

1. Allow code sharing between Metasploit Framework (MSF) and the commercial versions of Metasploit (Community, Express, Pro -- usually referred to collectively as "Pro")

2. Give developers a lightweight entry point to MSF's backend for use in developing tools that gather data intended for later use with Metasploit (e.g. specialized scanners).

3. Make it easy to keep commercial stuff private while increasing the functionality of the open-source tools we provide to the community.


## Usage

### Rails

In a Rails application, MetasploitDataModels acts a
[Rails Engine](http://edgeapi.rubyonrails.org/classes/Rails/Engine.html) and the models are available to application
just as if they were defined under `app/models`.  If your Rails appliation needs to modify the models, this can be done
using `ActiveSupport.on_load` hooks in initializers.  The block passed to on_load hook is evaluated in the context of the
model class, so defining method and including modules will work just like reopeninng the class, but
`ActiveSupport.on_load` ensures that the monkey patches will work after reloading in development mode.  Each class has a
different `on_load` name, which is just the class name converted to an underscored symbol, so `Mdm::ApiKey` runs the
`:mdm_api_key` load hooks, etc.

    # Gemfile
    gem :metasploiit_data_models, :git => git://github.com/rapid7/metasploit_data_models.git, :tag => 'v0.3.0'

    # config/initializers/metasploit_data_models.rb
    ActiveSupport.on_load(:mdm_api_key) do
      # Returns the String obfuscated token for display. Meant to avoid CSRF
      # api-key stealing attackes.
      def obfuscated_token
        token[0..3] + "****************************"
      end
    end
    
**This gem's `Rails::Engine` is not required automatically.** You'll need to also add the following to your `config/application.rb`:

    require 'metasploit_data_models/engine'

### Metasploit Framework

In Metasploit Framework, `MetasploitDataModels::Engine` is loaded, but the data models are only if the user wants to use
the database.

### Elsewhere

In Metasploit Pro, MDM is loaded via the metasploit_data_models gem: https://rubygems.org/gems/metasploit_data_models

An MRI and JRuby implementation is generated for all substantial updates.

## Developer Info

### Console
The gem includes a console based on [Pry](https://github.com/pry/pry/)

Give it a path to a working MSF database.yml file for full
ActiveRecord-based access to your data.

__Note:__ "development" mode is hardcoded into the console currently.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
