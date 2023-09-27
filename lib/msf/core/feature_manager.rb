# -*- coding: binary -*-
# frozen_string_literal: true

require 'rex/text'

module Msf
  ###
  #
  # The feature manager is responsible for managing feature flags that can change characteristics of framework.
  # Each feature will have a default value. The user can choose to override this default value if they wish.
  ###
  class FeatureManager

    include Singleton

    CONFIG_KEY = 'framework/features'
    WRAPPED_TABLES = 'wrapped_tables'
    DATASTORE_FALLBACKS = 'datastore_fallbacks'
    FULLY_INTERACTIVE_SHELLS = 'fully_interactive_shells'
    MANAGER_COMMANDS = 'manager_commands'
    METASPLOIT_PAYLOAD_WARNINGS = 'metasploit_payload_warnings'
    DEFAULTS = [
      {
        name: WRAPPED_TABLES,
        description: 'When enabled Metasploit will wordwrap all tables to fit into the available terminal width',
        default_value: true
      }.freeze,
      {
        name: FULLY_INTERACTIVE_SHELLS,
        description: 'When enabled you will have the option to drop into a fully interactive shell from within meterpreter',
        default_value: false
      }.freeze,
      {
        name: MANAGER_COMMANDS,
        description: 'When enabled you will have access to manager commands such as _servicemanager and _historymanager',
        default_value: false
      }.freeze,
      {
        name: DATASTORE_FALLBACKS,
        description: 'When enabled you can consistently set username across modules, instead of setting SMBUser/FTPUser/BIND_DN/etc',
        requires_restart: true,
        default_value: true
      }.freeze,
      {
        name: METASPLOIT_PAYLOAD_WARNINGS,
        description: 'When enabled Metasploit will output warnings about missing Metasploit payloads, for instance if they were removed by antivirus etc',
        requires_restart: true,
        default_value: false
      }.freeze
    ].freeze

    #
    # Initializes the feature manager.
    #
    def initialize
      @flag_lookup = DEFAULTS.each_with_object({}) do |feature, acc|
        if feature[:name] == WRAPPED_TABLES
          if feature[:default_value] == true
            Rex::Text::Table.wrap_tables!
          else
            Rex::Text::Table.unwrap_tables!
          end
        end

        key = feature[:name]
        acc[key] = feature.dup
      end
    end

    def all
      @flag_lookup.values.map do |feature|
        feature.slice(:name, :description).merge(enabled: enabled?(feature[:name]))
      end
    end

    # @param [String] name The feature name
    # @return [TrueClass,FalseClass] True if the flag is be enabled, false otherwise
    def enabled?(name)
      return false unless @flag_lookup[name]

      feature = @flag_lookup[name]
      feature.key?(:user_preference) ? feature[:user_preference] : feature[:default_value]
    end

    # @param [String] name The feature name
    # @return [TrueClass,FalseClass] True if the flag requires a console restart to work effectively
    def requires_restart?(name)
      return false unless @flag_lookup[name]

      @flag_lookup[name][:requires_restart] == true
    end

    def exists?(name)
      @flag_lookup.key?(name)
    end

    def names
      all.map { |feature| feature[:name] }
    end

    def set(name, value)
      return false unless @flag_lookup[name]

      @flag_lookup[name][:user_preference] = value

      if name == WRAPPED_TABLES
        if value
          Rex::Text::Table.wrap_tables!
        else
          Rex::Text::Table.unwrap_tables!
        end
      end
    end

    def load_config
      conf = Msf::Config.load
      conf.fetch(CONFIG_KEY, {}).each do |name, value|
        set(name, value == 'true')
      end
    end

    def save_config
      # Note, we intentionally omit features that have not explicitly been set by the user.
      config = Msf::Config.load
      old_config = config.fetch(CONFIG_KEY, {})
      new_config = @flag_lookup.values.each_with_object(old_config) do |feature, config|
        next unless feature.key?(:user_preference)

        config.merge!(feature[:name] => feature[:user_preference].to_s)
      end

      Msf::Config.save(CONFIG_KEY => new_config)
    end
  end
end
