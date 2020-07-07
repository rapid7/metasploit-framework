# -*- coding: binary -*-
# frozen_string_literal: true

require 'msf/core/plugin'

module Msf
  ###
  #
  # The feature manager is responsible for managing feature flags that can change characteristics of framework.
  #
  ###
  class FeatureManager

    include Framework::Offspring

    WRAPPED_TABLES = 'wrapped_tables'
    DEFAULTS = [
      {
        name: 'wrapped_tables',
        description: 'When enabled Metasploit will wordwrap all tables to fit into the available terminal width',
        enabled: false
      }.freeze
    ].freeze

    #
    # Initializes the feature manager.
    #
    def initialize(framework)
      @framework = framework
      @flag_lookup = DEFAULTS.each_with_object({}) do |feature, acc|
        key = feature[:name]
        acc[key] = feature.dup
      end
    end

    def all
      @flag_lookup.values
    end

    def enabled?(name)
      return false unless @flag_lookup[name]

      @flag_lookup[name][:enabled] == true
    end

    def exists?(name)
      @flag_lookup.key?(name)
    end

    def names
      all.map { |feature| feature[:name] }
    end

    def set(name, value)
      return false unless @flag_lookup[name]

      @flag_lookup[name][:enabled] = value

      if name == WRAPPED_TABLES
        if value
          Rex::Text::Table.wrap_tables!
        else
          Rex::Text::Table.unwrap_tables!
        end
      end
    end
  end
end
