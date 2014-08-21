#
# Gems
#

require 'active_support/core_ext/module/introspection'

#
# Project
#

require 'metasploit/framework/command'
require 'metasploit/framework/parsed_options'
require 'metasploit/framework/require'

# Based on pattern used for lib/rails/commands in the railties gem.
class Metasploit::Framework::Command::Base
  #
  # Attributes
  #

  # @!attribute [r] application
  #   The Rails application for metasploit-framework.
  #
  #   @return [Metasploit::Framework::Application]
  attr_reader :application

  # @!attribute [r] parsed_options
  #   The parsed options from the command line.
  #
  #   @return (see parsed_options)
  attr_reader :parsed_options

  #
  # Class Methods
  #

  # @note {require_environment!} should be called to load
  #   `config/application.rb` to so that the RAILS_ENV can be set from the
  #   command line options in `ARGV` prior to `Rails.env` being set.
  # @note After returning, `Rails.application` will be defined and configured.
  #
  # Parses `ARGV` for command line arguments to configure the
  # `Rails.application`.
  #
  # @return (see parsed_options)
  def self.require_environment!
    parsed_options = self.parsed_options
    # RAILS_ENV must be set before requiring 'config/application.rb'
    parsed_options.environment!
    ARGV.replace(parsed_options.positional)

    # allow other Rails::Applications to use this command
    if !defined?(Rails) || Rails.application.nil?
      # @see https://github.com/rails/rails/blob/v3.2.17/railties/lib/rails/commands.rb#L39-L40
      require Pathname.new(__FILE__).parent.parent.parent.parent.parent.join('config', 'application')
    end

    # have to configure before requiring environment because
    # config/environment.rb calls initialize! and the initializers will use
    # the configuration from the parsed options.
    parsed_options.configure(Rails.application)

    Rails.application.require_environment!

    parsed_options
  end

  def self.parsed_options
    parsed_options_class.new
  end

  def self.parsed_options_class
    @parsed_options_class ||= parsed_options_class_name.constantize
  end

  def self.parsed_options_class_name
    @parsed_options_class_name ||= "#{parent.parent}::ParsedOptions::#{name.demodulize}"
  end

  def self.start
    parsed_options = require_environment!
    new(application: Rails.application, parsed_options: parsed_options).start
  end

  #
  # Instance Methods
  #

  # @param attributes [Hash{Symbol => ActiveSupport::OrderedOptions,Rails::Application}]
  # @option attributes [Rails::Application] :application
  # @option attributes [ActiveSupport::OrderedOptions] :parsed_options
  # @raise [KeyError] if :application is not given
  # @raise [KeyError] if :parsed_options is not given
  def initialize(attributes={})
    @application = attributes.fetch(:application)
    @parsed_options = attributes.fetch(:parsed_options)
  end

  # @abstract Use {#application} to start this command.
  #
  # Starts this command.
  #
  # @return [void]
  # @raise [NotImplementedError]
  def start
    raise NotImplementedError
  end
end
