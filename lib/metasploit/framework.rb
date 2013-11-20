require 'metasploit/model'

# Top-level namespace that is shared between {Metasploit::Framework
# metasploit-framework} and pro, which uses Metasploit::Pro.
module Metasploit
  # Supports Rails and Rails::Engine like access to metasploit-framework so it
  # works in compatible manner with activerecord's rake tasks and other
  # railties.
  module Framework
    extend Metasploit::Model::Configured

    pathname = Pathname.new(__FILE__)
    configuration.root = pathname.parent.parent.parent

    configuration.autoload.relative_paths << File.join('app', 'validators')

    # Returns the environment for {Metasploit::Framework}.  Checks
    # `METASPLOIT_FRAMEWORK_ENV` environment variable for value.  Defaults to
    # `'development'` if `METASPLOIT_FRAMEWORK_ENV` is not set in the
    # environment variables.
    #
    # {env} is a ActiveSupport::StringInquirer like `Rails.env` so it can be
    # queried for its value.
    #
    # @example check if environment is development
    #   if Metasploit::Framework.env.development?
    #     # runs only when in development
    #   end
    #
    # @return [ActiveSupport::StringInquirer] the environment name
    def self.env
      unless instance_variable_defined? :@env
        name = ENV['METASPLOIT_FRAMEWORK_ENV']
        name ||= 'development'
        @env = ActiveSupport::StringInquirer.new(name)
      end

      @env
    end

    def self.setup
      super

      ActiveSupport::Deprecation.behavior = ->(message, callstack){
        wlog(message)
        dlog(callstack.join('\n'))
      }
    end
  end
end

Metasploit::Framework.setup
