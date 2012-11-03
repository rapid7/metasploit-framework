#MetasploitDataModels

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
just as if they were defined under app/models.  If your Rails appliation needs to modify the models, this can be done
using ActiveSupport.on_load hooks in initializers.  The block passed to on_load hook is evaluated in the context of the
model class, so defining method and including modules will work just like reopeninng the class, but
ActiveSupport.on_load ensures that the monkey patches will work after reloading in development mode.  Each class has a
different on_load name, which is just the class name converted to an underscored symbol, so Mdm::ApiKey runs the
:mdm_api_key load hooks, etc.

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

### Metasploit Framework

In Metasploit Framework, `MetasploitDataModels.require_models` is called by the `Msf::DbManager` to use the data models
only if the user wants to use the database.

### Elsewhere

__NOTE: This isn't in RubyGems yet.  Using a Gemfile entry pointing to this repo (i.e., using
[Bundler](http://gembundler.com)) is the suggested option for now.__

Usage outside of Rapid7 is still alpha, as reflected in the pre-1.0.0 version, and we're not making many promises.  That
being said, usage is easy:

    connection_info = YAML.load_file("path/to/rails-style/db_config_file")
    ActiveRecord::Base.establish_connection(connection_info['development'])
    MetasploitDataModels.require_models

Basically you need to do the following things:

1. Establish an ActiveRecord connection.  A Rails __config/database.yml__ is ideal for this.
2. `MetasploitDataModels.require_models`


## Developer Info

### Console
The gem includes a console based on [Pry](https://github.com/pry/pry/)

Give it a path to a working MSF database.yml file for full
ActiveRecord-based access to your data.

__Note:__ "development" mode is hardcoded into the console currently.
