require 'rails'

# Refinement that returns engines method to Rails::Engine::Railties
# so that we can access the engines deprecated in Rails 4.1

module Metasploit
  module Concern
    # Rails engine for Metasploit::Concern that sets up an initializer to load the concerns from app/concerns in other
    # Rails engines.
    class Engine < ::Rails::Engine
      #
      # `config`
      #

      # @see http://viget.com/extend/rails-engine-testing-with-rspec-capybara-and-factorygirl
      config.generators do |g|
        g.assets false
        g.helper false
        g.test_framework :rspec, fixture: false
      end

      #
      # `initializer`s
      #

      initializer 'metasploit_concern.load_concerns' do
        application = Rails.application
        engines = application.railties._all.select{|rt| rt.is_a? Rails::Engine}

        # application is an engine
        engines = [application, *engines]

        engines.each do |engine|
          concerns_path = engine.paths['app/concerns']
          if concerns_path
            if concerns_path.eager_load?
              raise Metasploit::Concern::Error::EagerLoad, engine
            end

            unless concerns_path.autoload?
              raise Metasploit::Concern::Error::SkipAutoload, engine
            end

            concerns_directories = concerns_path.existent_directories

            concerns_directories.each do |concerns_directory|
              concerns_pathname = Pathname.new(concerns_directory)
              loader = Metasploit::Concern::Loader.new(root: concerns_pathname)
              loader.register
            end
          end
        end
      end

      isolate_namespace Metasploit::Concern
    end
  end
end
