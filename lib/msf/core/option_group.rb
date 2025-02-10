# -*- coding: binary -*-

module Msf
  class OptionGroup

    # @return [String] Name for the group
    attr_accessor :name
    # @return [String] Description to be displayed to the user
    attr_accessor :description
    # @return [Array<String>] List of datastore option names
    attr_accessor :option_names
    # @return [Array<String>] List of options that if present must have a value set
    attr_accessor :required_options

    # @param name [String] Name for the group
    # @param description [String] Description to be displayed to the user
    # @param option_names [Array<String>] List of datastore option names
    # @param required_options [Array<String>] List of options that if present must have a value set
    def initialize(name:, description:, option_names: [], required_options: [])
      self.name = name
      self.description = description
      self.option_names = option_names
      self.required_options = required_options
    end

    # @param option_name [String] Name of the datastore option to be added to the group
    def add_option(option_name)
      @option_names << option_name
    end

    # @param option_names [Array<String>] List of datastore option names to be added to the group
    def add_options(option_names)
      @option_names.concat(option_names)
    end

    # Validates that any registered and required options are set
    #
    # @param options [Array<Msf::OptBase>] A modules registered options
    # @param datastore [Msf::DataStore|Msf::DataStore] A modules datastore
    def validate(options, datastore)
      issues = {}
      required_options.each do |option_name|
        if options[option_name] && !datastore[option_name]
          issues[option_name] = "#{option_name} must be specified"
        end
      end
      raise Msf::OptionValidateError.new(issues.keys.to_a, reasons: issues) unless issues.empty?
    end
  end
end
