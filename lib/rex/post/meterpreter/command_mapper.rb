# -*- coding: binary -*-

require 'rex/post/meterpreter/extension_mapper'

module Rex
module Post
module Meterpreter

class CommandMapper

  def self.get_command_id(name)
    name.downcase!

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

  def self.get_command_name(id)
    extension_id = id - (id % COMMAND_ID_RANGE)
    if extension_id == 0  # this is the meterpreter core
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

  def self.get_command_names(*extensions)
    extensions = Rex::Post::Meterpreter::ExtensionMapper.get_extension_names if extensions.empty?

    command_names = []
    extensions.each do |mod_name|
      mod_name.downcase!

      if mod_name == 'core'
        mod = Rex::Post::Meterpreter
      else
        begin
          mod = Rex::Post::Meterpreter::ExtensionMapper.get_extension_module(mod_name)
        rescue RuntimeError
          next
        end
      end

      command_names += mod.constants.select { |name| name.to_s.start_with?("COMMAND_ID_#{mod_name.upcase}") }.map { |name| name.to_s.delete_prefix('COMMAND_ID_').downcase }
    end

    command_names
  end

end

end
end
end
