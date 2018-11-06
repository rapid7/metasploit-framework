# Metasploit::Concern [![Build Status](https://travis-ci.org/rapid7/metasploit-concern.png)](https://travis-ci.org/rapid7/metasploit-concern)[![Code Climate](https://codeclimate.com/github/rapid7/metasploit-concern.png)](https://codeclimate.com/github/rapid7/metasploit-concern)[![Coverage Status](https://coveralls.io/repos/rapid7/metasploit-concern/badge.png)](https://coveralls.io/r/rapid7/metasploit-concern)[![Dependency Status](https://gemnasium.com/rapid7/metasploit-concern.png)](https://gemnasium.com/rapid7/metasploit-concern)[![Gem Version](https://badge.fury.io/rb/metasploit-concern.png)](http://badge.fury.io/rb/metasploit-concern)

`Metasploit::Concern` allows you to define concerns in `app/concerns` that will automatically be included in matching classes.  It can be used to automate adding new associations to `ActiveRecord::Base` models from gems and `Rails::Engine`s.

## Versioning

`Metasploit::Concern` is versioned using [semantic versioning 2.0](http://semver.org/spec/v2.0.0.html).  Each branch should set `Metasploit::Concern::Version::PRERELEASE` to the branch SUMMARY, while master should have no `PRERELEASE` and the `PRERELEASE` section of `Metasploit::Concern::VERSION` does not exist.

## Installation

Add this line to your application's `Gemfile`:

    gem 'metasploit-concern'

And then execute:

    $ bundle
    
**This gem's `Rails::Engine` is not required automatically.** You'll need to also add the following to your `config/application.rb`:

    require 'metasploit/concern/engine'

Or install it yourself as:

    $ gem install metasploit-concern
    


## Supporting concerns

`Metasploit::Concern` support is a cooperative effort that involves the classes from the gem being setup to allow downstream dependents to inject concerns.

In order for `Metasploit::Concern` to load concerns for `app/concerns`, the class on which `Module#include` will be called must support `ActiveSupport` load hooks with a specific name format.  You can run the appropriate load hooks at the bottom of the class body:

    class GemNamespace::GemClass < ActiveRecord::Base
      # class body

      Metasploit::Concern.run(self)
    end

### Testing

Include the shared examples from `Metasploit::Concern` in your `spec_helper.rb`:


    Dir[Metasploit::Concern.root.join("spec/support/**/*.rb")].each do |f|
      require f
    end


To verify that your classes call `Metasploit::Concern.run` correctly, you can use the `'Metasploit::Concern.run'` shared example:

    # spec/app/models/gem_namespace/gem_class_spec.rb
    describe GemNamespace::GemClass do
      it_should_behave_like 'Metasploit::Concern.run'
    end

## Using concerns

Concerns are added in downstream dependents of gems that support concerns.  These dependents can be a `Rails::Engines` or full `Rails::Application`.

### app/concerns

#### Rails::Application

Add this line to your application's `config/application.rb`:

    config.paths.add 'app/concerns', autoload: true

Or if you're already using `config.autoload_paths +=`:

    config.autoload_paths += config.root.join('app', 'concerns')

#### Rails::Engine

Add this line to your engine's class body:

    module EngineNamespace
      class Engine < ::Rails::Engine
        config.paths.add 'app/concerns', autoload: true
      end
    end

### Concerns

Define concerns for class under `app/concerns` by creating files under directories named after the namespaced class names:

    $ mkdir -p app/concerns/gem_namespace/gem_class
    $ edit app/concerns/gem_namespace/gem_class/my_concern.rb

Inside each concern, make sure the `module` name matches file name:

    module GemNamespace::GemClass::MyConcern
      ...
    end

Each concern is included using `Module#include` which means that the `included` method on each concern will be called.  Using `ActiveSupport::Concern` allow you to add new associations and or validations to `ActiveRecord::Base` subclass:

    module GemNamespace::GemClass::MyConcern
      extend ActiveSupport::Concern

      included do
        #
        # Associations
        #

        # @!attribute widgets
        #  Widgets for this gem_class.
        #
        #  @return [ActiveRecord::Relation<Widget>]
        has_many :widgets,
                 class_name: 'Widget',
                 dependent: :destroy,
                 inverse_of :gem_namespace_gem_class
      end
    end
    
### initializers

`Metasploit::Concern::Engine` defines the `'metasploit_concern.load_concerns'` initializer, which sets up `ActiveSupport.on_load` callbacks.  If you depend on a feature from a concern in your initializers, it is best to have the initializer declare that it needs to be run after `'metasploit_concern.load_concerns`:

    initializer 'application_or_engine_namespace.depends_on_concerns', after: 'metasploit_concern.load_concerns' do
      if GemNamespace::GemClass.primary.widgets.empty?
        logger.info('No Widgets on the primary GemClass!')
      end
    end

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)
