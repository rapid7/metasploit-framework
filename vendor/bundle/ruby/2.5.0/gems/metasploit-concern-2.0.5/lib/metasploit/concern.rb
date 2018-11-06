#
# Gems
#
# gems must load explicitly any gem declared in gemspec
# @see https://github.com/bundler/bundler/issues/2018#issuecomment-6819359
#
#

# `String#underscore``
require 'active_support/core_ext/string/inflections'
# `ActiveSupport::Autoload`
require 'active_support/dependencies/autoload'
# `ActiveSupport.run_load_hooks`
require 'active_support/lazy_load_hooks'

#
# Project
#

require 'metasploit/concern/version'

# Shared namespace for metasploit gems; used in {https://github.com/rapid7/metasploit-concern metasploit-concern},
# {https://github.com/rapid7/metasploit-framework metasploit-framework}, and
# {https://github.com/rapid7/metasploit-model metasploit-model}
module Metasploit
  # Automates the inclusion of concerns into classes and models from other `Rail::Engine`s by use of an app/concerns
  # directory in the `Rails::Engine` that declares the concerns.
  #
  # The `Class` or `Module` must support the use of concerns by calling {run}.
  #
  # @example engine_that_supports_concerns/app/models/model_that_supports_concerns.rb
  #   class EngineThatSupportsConcerns::ModelThatSupportsConcerns
  #     # declared as last statement in body so that concerns can redefine everything in class
  #     Metasploit::Concern.run(self)
  #   end
  #
  # To include concerns from a Rails::Application add 'app/concerns' to paths and then declare concerns under
  # app/concerns.
  #
  # @example config/application.rb
  #   config.paths.add 'app/concerns', autoload: true
  #
  # @example Concern declared in application
  #   # app/concerns/engine_that_supports_concerns/model_that_supports_concerns/concern_from_application.rb
  #   module EngineThatSupportsConcerns::ModelThatSupportsConcerns::ConcernFromApplication
  #     extend ActiveSupport::Concern
  #
  #     included do
  #       # run with self equal to EngineThatSupportsConcerns::ModelThatSupportsConcerns, but at the end of the class
  #       # definition, instead of at the beginning as would be the case with
  #       #   class EngineThatSupportsConcerns::ModelThatSupportsConcerns
  #       #     include EngineThatSupportsConcerns::ModelThatSupportsConcerns::ModelThatSupportsConcerns
  #       #
  #       #     # body
  #       #   end
  #     end
  #   end
  #
  # To include concerns from a Rails::Engine add 'app/concerns' to the paths and then declare concerns under
  # app/concerns.
  #
  # @example Rails::Engine configuration for app/concerns
  #   # engine_defining_concerns/lib/engine_defining_concerns/engine.rb
  #   module EngineDefiningConcerns
  #     class Engine < Rails::Engine
  #       config.paths.add 'app/concerns', autoload: true
  #     end
  #   end
  #
  # @example Concern declared in Rails::Engine
  #   # engine_defining_concerns/app/concerns
  #   module EngineThatSupportsConcerns::ModelThatSupportsConcerns::ConcernFromEngine
  #     extend ActiveSupport::Concern
  #
  #     included do
  #       # run with self equal to EngineThatSupportsConcerns::ModelThatSupportsConcerns, but at the end of the class
  #       # definition, instead of at the beginning as would be the case with
  #       #   class EngineThatSupportsConcerns::ModelThatSupportsConcerns
  #       #     include EngineThatSupportsConcerns::ModelThatSupportsConcerns::ModelThatSupportsConcerns
  #       #
  #       #     # body
  #       #   end
  #     end
  #   end
  module Concern
    extend ActiveSupport::Autoload

    autoload :Error
    autoload :EagerLoadError

    # @note If `Rails` is loaded and {Metasploit::Concern::Engine} is defined, just use
    #   `Metasploit::Concern::Engine.root`.
    #
    # The root of the `metasploit-concern` gem's file tree.
    #
    # @return [Pathname]
    def self.root
      @root ||= Pathname.new(__FILE__).parent.parent.parent
    end

    # @note As `ActiveSupport.run_load_hooks` is used, it is safe to call {run} prior to {Metasploit::Concern}'s
    # initializer {Metasploit::Concern::Loader#register registering} all the load hooks as any late load hooks will run
    # as they are registered.
    #
    # @note `klass` must have a `Module#name` so that the load hook symbol can be derived.
    #
    # Runs the load hooks setup to include app/concerns concerns this `klass`.
    #
    # @param klass [Class] A class that should support loading concerns from app/concerns.
    # @return [void]
    def self.run(klass)
      load_hook_name = klass.name.underscore.gsub('/', '_').to_sym
      ActiveSupport.run_load_hooks(load_hook_name, klass)
    end
  end
end
