#
# Standard Library
#

require 'optparse'

#
# Gems
#

require 'active_support/ordered_options'

#
# Project
#

require 'metasploit/framework/database'
require 'metasploit/framework/parsed_options'

# Options parsed from the command line that can be used to change the
# `Metasploit::Framework::Application.config` and `Rails.env`
class Metasploit::Framework::ParsedOptions::Base
  #
  # CONSTANTS
  #

  # msfconsole boots in production mode instead of the normal rails default of
  # development.
  DEFAULT_ENVIRONMENT = 'production'

  #
  # Attributes
  #

  attr_reader :positional

  #
  # Instance Methods
  #

  def initialize(arguments=ARGV)
    begin
      @positional = option_parser.parse(arguments)
    rescue OptionParser::InvalidOption
      puts "ERROR: Invalid command line option provided."
      puts option_parser
      exit(1)
    end
  end

  # Translates {#options} to the `application`'s config
  #
  # @param application [Rails::Application]
  # @return [void]
  def configure(application)
    application.config['config/database'] = options.database.config
  end

  # Sets the `RAILS_ENV` environment variable.
  #
  # 1. If the -E/--environment option is given, then its value is used.
  # 2. The default value, 'production', is used.
  #
  # @return [void]
  def environment!
    if defined?(Rails) && Rails.instance_variable_defined?(:@_env) && Rails.env != options.environment
      raise "#{self.class}##{__method__} called too late to set RAILS_ENV: Rails.env already memoized"
    end

    ENV['RAILS_ENV'] = options.environment
  end

  # Options parsed from
  #
  # @return [ActiveSupport::OrderedOptions]
  def options
    unless @options
      options = ActiveSupport::OrderedOptions.new

      options.database = ActiveSupport::OrderedOptions.new

      options.database.config = Metasploit::Framework::Database.configurations_pathname.try(:to_path)
      options.database.disable = false
      options.database.migrations_paths = []

      # If RAILS_ENV is set, then it will be used, but if RAILS_ENV is set and the --environment option is given, then
      # --environment value will be used to reset ENV[RAILS_ENV].
      options.environment = ENV['RAILS_ENV'] || DEFAULT_ENVIRONMENT

      options.framework = ActiveSupport::OrderedOptions.new
      options.framework.config = nil

      options.modules = ActiveSupport::OrderedOptions.new
      options.modules.defer_loads = false
      options.modules.path = nil

      @options = options
    end

    @options
  end

  private

  # Parses arguments into {#options}.
  #
  # @return [OptionParser]
  def option_parser
    @option_parser ||= OptionParser.new { |option_parser|
      option_parser.separator ''
      option_parser.separator 'Common options:'

      option_parser.on(
          '-E',
          '--environment ENVIRONMENT',
          %w{development production test},
          "Set Rails environment, defaults to RAIL_ENV environment variable or 'production'"
      ) do |environment|
        options.environment = environment
      end

      option_parser.separator ''
      option_parser.separator 'Database options:'

      option_parser.on(
          '-M',
          '--migration-path DIRECTORY',
          'Specify a directory containing additional DB migrations'
      ) do |directory|
        options.database.migrations_paths << directory
      end

      option_parser.on('-n', '--no-database', 'Disable database support') do
        options.database.disable = true
      end

      option_parser.on(
          '-y',
          '--yaml PATH',
          'Specify a YAML file containing database settings'
      ) do |path|
        options.database.config = path
      end

      option_parser.separator ''
      option_parser.separator 'Framework options:'


      option_parser.on('-c', '-c FILE', 'Load the specified configuration file') do |file|
        options.framework.config = file
      end

      option_parser.on(
          '-v','-V',
          '--version',
          'Show version'
      ) do
        options.subcommand = :version
      end

      option_parser.separator ''
      option_parser.separator 'Module options:'

      option_parser.on(
          '--defer-module-loads',
          'Defer module loading unless explicitly asked.'
      ) do
        options.modules.defer_loads = true
      end

      option_parser.on(
          '-m',
          '--module-path DIRECTORY',
          'Load an additional module path'
      ) do |directory|
        options.modules.path = directory
      end

      #
      # Tail
      #

      option_parser.separator ''
      option_parser.on_tail('-h', '--help', 'Show this message') do
        puts option_parser
        exit
      end
    }
  end
end
