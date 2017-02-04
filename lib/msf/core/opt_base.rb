# -*- coding: binary -*-
require 'resolv'
require 'msf/core'
require 'rex/socket'

module Msf

  ###
  #
  # The base class for all options.
  #
  ###
  class OptBase

    #
    # Initializes a named option with the supplied attribute array.
    # The array is composed of three values.
    #
    # attrs[0] = required (boolean type)
    # attrs[1] = description (string)
    # attrs[2] = default value
    # attrs[3] = possible enum values
    # attrs[4] = Regex to validate the option
    #
    def initialize(in_name, attrs = [])
      self.name     = in_name
      self.advanced = false
      self.evasion  = false
      self.required = attrs[0] || false
      self.desc     = attrs[1]
      self.default  = attrs[2]
      self.enums    = [ *(attrs[3]) ].map { |x| x.to_s }
      regex_temp    = attrs[4] || nil
      if regex_temp
        # convert to string
        regex_temp = regex_temp.to_s if regex_temp.is_a? Regexp
        # remove start and end character, they will be added later
        regex_temp = regex_temp.sub(/^\^/, '').sub(/\$$/, '')
        # Add start and end marker to match the whole regex
        regex_temp = "^#{regex_temp}$"
        begin
          Regexp.compile(regex_temp)
          self.regex = regex_temp
        rescue RegexpError, TypeError => e
          raise("Invalid Regex #{regex_temp}: #{e}")
        end
      end
    end

    #
    # Returns true if this is a required option.
    #
    def required?
      return required
    end

    #
    # Returns true if this is an advanced option.
    #
    def advanced?
      return advanced
    end

    #
    # Returns true if this is an evasion option.
    #
    def evasion?
      return evasion
    end

    #
    # Returns true if the supplied type is equivalent to this option's type.
    #
    def type?(in_type)
      return (type == in_type)
    end

    #
    # Returns true if this option can be validated on assignment
    #
    def validate_on_assignment?
      true
    end

    #
    # If it's required and the value is nil or empty, then it's not valid.
    #
    def valid?(value, check_empty: true)
      if check_empty && required?
        # required variable not set
        return false if (value.nil? || value.to_s.empty?)
      end
      if regex
        return !!value.match(regex)
      end
      return true
    end

    #
    # Returns true if the value supplied is nil and it's required to be
    # a valid value
    #
    def empty_required_value?(value)
      return (required? and value.nil?)
    end

    #
    # Normalizes the supplied value to conform with the type that the option is
    # conveying.
    #
    def normalize(value)
      value
    end

    #
    # Returns a string representing a user-friendly display of the chosen value
    #
    def display_value(value)
      value.to_s
    end

    #
    # The name of the option.
    #
    attr_reader   :name
    #
    # Whether or not the option is required.
    #
    attr_reader   :required
    #
    # The description of the option.
    #
    attr_reader   :desc
    #
    # The default value of the option.
    #
    attr_reader   :default
    #
    # Storing the name of the option.
    #
    attr_writer   :name
    #
    # Whether or not this is an advanced option.
    #
    attr_accessor :advanced
    #
    # Whether or not this is an evasion option.
    #
    attr_accessor :evasion
    #
    # The module or entity that owns this option.
    #
    attr_accessor :owner
    #
    # The list of potential valid values
    #
    attr_accessor :enums
    #
    # A optional regex to validate the option value
    #
    attr_accessor :regex

    protected

    attr_writer   :required, :desc, :default # :nodoc:
  end

end

