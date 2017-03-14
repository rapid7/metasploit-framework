# @note needs to use explicit nesting. so this file can be loaded directly without loading 'metasploit/framework', this
#   file can be used prior to Bundler.require.
module Metasploit
  module Framework
    # Extension to `Kernel#require` behavior.
    module Require
      #
      # Module Methods
      #

      # Tries to require `name`.  If a `LoadError` occurs, then `without_warning` is printed to standard error using
      # `Kernel#warn`, along with instructions for reinstalling the bundle.  If a `LoadError` does not occur, then
      # `with_block` is called.
      #
      # @param name [String] the name of the library to `Kernel#require`.
      # @param without_warning [String] warning to print if `name` cannot be required.
      # @yield block to run when `name` requires successfully
      # @yieldreturn [void]
      # @return [void]
      def self.optionally(name, without_warning)
        begin
          require name
        rescue LoadError
          warn without_warning
          warn "Bundle installed '--without #{Bundler.settings.without.join(' ')}'"
          warn "To clear the without option do `bundle install --without ''` " \
           "(the --without flag with an empty string) or " \
           "`rm -rf .bundle` to remove the .bundle/config manually and " \
           "then `bundle install`"
        else
          if block_given?
            yield
          end
        end
      end

      # Tries to `require 'active_record/railtie'` to define the activerecord Rails initializers and rake tasks.
      #
      # @example Optionally requiring 'active_record/railtie'
      #   require 'metasploit/framework/require'
      #
      #   class MyClass
      #     def setup
      #       if database_enabled
      #         Metasploit::Framework::Require.optionally_active_record_railtie
      #       end
      #     end
      #   end
      #
      # @return [void]
      def self.optionally_active_record_railtie
        if ::Rails.application.config.paths['config/database'].any?
          optionally(
            'active_record/railtie',
            'activerecord not in the bundle, so database support will be disabled.'
          )
        else
          warn 'Could not find database.yml, so database support will be disabled.'
        end
      end

      # Tries to `require 'metasploit/credential'` and include `Metasploit::Credential::Creation` in the
      # `including_module`.
      #
      # @param including_module [Module] `Class` or `Module` that wants to `include Metasploit::Credential::Creation`.
      # @return [void]
      def self.optionally_include_metasploit_credential_creation(including_module)
        optionally(
            'metasploit/credential',
            "metasploit-credential not in the bundle, so Metasploit::Credential creation will fail for #{including_module.name}"
        ) do
          including_module.send(:include, Metasploit::Credential::Creation)
        end
      end

      # Tries to require gems necessary for using a database with the framework.
      #
      # @example
      #   Metasploit::Framework::Require.optionally_require_metasploit_db_gems
      #
      # @return [void]
      def self.optionally_require_metasploit_db_gem_engines
        optionally(
            'metasploit/credential',
            'metasploit-credential not in the bundle',
        ) do
          require 'metasploit/credential/engine'
        end

        optionally(
          'metasploit_data_models',
          'metasploit_data_models not in the bundle'
        ) do
          require 'metasploit_data_models/engine'
        end
      end

      #
      # Instance Methods
      #

      # Tries to `require 'metasploit/credential/creation'` and include it in this `Class` or `Module`.
      #
      # @example Using in a `Module`
      #   require 'metasploit/framework/require'
      #
      #   module MyModule
      #     extend Metasploit::Framework::Require
      #
      #     optionally_include_metasploit_credential_creation
      #   end
      #
      # @return [void]
      def optionally_include_metasploit_credential_creation
        Metasploit::Framework::Require.optionally_include_metasploit_credential_creation(self)
      end
    end
  end
end
