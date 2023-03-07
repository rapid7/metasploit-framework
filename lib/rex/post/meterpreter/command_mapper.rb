# -*- coding: binary -*-

require 'rex/post/meterpreter/extension_mapper'
require 'rex/post/meterpreter/core_ids'
require 'rex/post/meterpreter/client_core'

module Rex
module Post
module Meterpreter

class CommandMapper
  @@cached_tlv_types = {}

  # Get the numeric command ID for the specified command name.
  #
  # @param [String] name The name of the command to retrieve the ID for. This
  #   parameter is case insensitive.
  # @return [Integer, nil] The command ID or nil if the name does not exist.
  def self.get_command_id(name)
    name = name.downcase

    return nil unless name.include?('_')

    mod_name, cmd_name = name.split('_', 2)
    if mod_name == 'core'
      mod = Rex::Post::Meterpreter
    else
      mod = Rex::Post::Meterpreter::ExtensionMapper.get_extension_module(mod_name)
    end

    return nil unless mod

    const_name = "COMMAND_ID_#{mod_name.upcase}_#{cmd_name.upcase}"
    return nil unless mod.const_defined?(const_name)

    mod.const_get(const_name)
  end

  # Get the string command name for the specified command ID.
  #
  # @param [Integer] id The ID of the command to retrieve the name for.
  # @return [String, nil] The command name or nil if the ID does not exist.
  def self.get_command_name(id)
    extension_id = id - (id % COMMAND_ID_RANGE)
    if extension_id == Rex::Post::Meterpreter::ClientCore.extension_id  # this is the meterpreter core which is not exactly an extension.
      mod = Rex::Post::Meterpreter
    else
      mod_name = Rex::Post::Meterpreter::ExtensionMapper.get_extension_name(extension_id)
      mod = Rex::Post::Meterpreter::ExtensionMapper.get_extension_module(mod_name)
    end

    return nil unless mod

    command_name = mod.constants.select { |c| c.to_s.start_with?('COMMAND_ID_') }.find { |c| id == mod.const_get(c) }

    return nil unless command_name

    command_name.to_s.delete_prefix('COMMAND_ID_').downcase
  end

  # Get all of the string command names for the specified extensions.
  #
  # @param [Array<String>] extensions The names of the extensions to retrieve
  #   all of the command names for. The extension names are case insensitive. If
  #   no extensions are specified, all extensions will be enumerated.
  # @return [Array<String>] An array of all of the enumerated command names.
  def self.get_command_names(*extensions)
    self.get_commands(*extensions).keys
  end

  # Get a hash of all command name strings mapped to their numeric IDs.
  #
  # @param [Array<String>] extensions The names of the extensions to retrieve
  #   all of the commands for. The extension names are case insensitive. If
  #   no extensions are specified, all extensions will be enumerated.
  # @return [Hash<String, Integer>] An hash of all of the enumerated commands.
  def self.get_commands(*extensions)
    extensions = ['core'] + Rex::Post::Meterpreter::ExtensionMapper.get_extension_names if extensions.empty?

    commands = {}
    extensions.each do |mod_name|
      mod_name = mod_name.downcase

      if mod_name == 'core'
        mod = Rex::Post::Meterpreter
      else
        begin
          mod = Rex::Post::Meterpreter::ExtensionMapper.get_extension_module(mod_name)
        rescue RuntimeError
          next
        end
      end

      constants = mod.constants.select { |name| name.to_s.start_with?("COMMAND_ID_#{mod_name.upcase}") }
      commands.merge!(constants.map { |name| [name.to_s.delete_prefix('COMMAND_ID_').downcase, mod.const_get(name)] }.to_h)
    end

    commands
  end


  # Get the TLV Type symbols that are defined with the value
  # Potential return values are [], [:TLV_TYPE_A], and [:TLV_TYPE_A, :PACKET_TYPE_B]
  #
  # Returning an array is a solution to having multiple TLV types having the same value, as documented here:
  # https://github.com/rapid7/metasploit-framework/issues/16267
  #
  # @param Integer value The value of the TLV type to retrieve the TLV type names for.
  # @return [Array<Symbol>] An array of symbols of all TLV types that are defined with the value. Can be empty.
  def self.get_tlv_names(value)
    return @@cached_tlv_types[value] unless @@cached_tlv_types[value].nil? || @@cached_tlv_types[value].empty?

    # Default to arrays that contain TLV Types, so that we only deal with one data type
    @@cached_tlv_types = Hash.new { |h, k| h[k] = Set.new }

    available_modules = [
      ::Rex::Post::Meterpreter,
      *::Rex::Post::Meterpreter::ExtensionMapper.get_extension_klasses,
      # Railgun is a special case that defines extra TLV_TYPES inside an extension
      Rex::Post::Meterpreter::Extensions::Stdapi::Railgun
    ].uniq

    available_modules.each do |mod|
      mod.constants.each do |const|
        next unless const.to_s.start_with?('TLV_TYPE_') || const.to_s.start_with?('PACKET_')

        @@cached_tlv_types[mod.const_get(const)] << const
      end
    end

    @@cached_tlv_types[value]
  end
end

end
end
end
