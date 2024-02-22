# -*- coding: binary -*-

module Msf
  class OptionGroup

    # @return [String] Name for the group
    attr_accessor :name
    # @return [String] Description to be displayed to the user
    attr_accessor :description
    # @return [Array<String>] List of datastore option names
    attr_accessor :option_names

    # @param name [String] Name for the group
    # @param description [String] Description to be displayed to the user
    # @param option_names [Array<String>] List of datastore option names
    def initialize(name:, description:, option_names: [])
      self.name = name
      self.description = description
      self.option_names = option_names
    end

    # @param option_name [String] Name of the datastore option to be added to the group
    def add_option(option_name)
      @option_names << option_name
    end

    # @param option_names [Array<String>] List of datastore option names to be added to the group
    def add_options(option_names)
      @option_names.concat(option_names)
    end
  end
end
