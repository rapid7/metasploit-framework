# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

class ExtensionMapper

  @@klasses = {}

  # Get the names of all of the extensions.
  #
  # @return [Array<String>] An array of all of the extension names.
  def self.get_extension_names
    base = ::File.join(File.dirname(__dir__), 'meterpreter/extensions')
    ::Dir.entries(base).select do |e|
      ::File.directory?(::File.join(base, e)) && !['.', '..'].include?(e)
    end
  end

  # Get the numeric ID for the specified extension name.
  #
  # @param [String] name The name of the extension to retrieve the ID for. This
  #   parameter is case insensitive.
  # @return [Integer, nil] The extension ID or nil if the name does not exist.
  def self.get_extension_id(name)
    begin
      k = self.get_extension_klass(name)
    rescue RuntimeError
      return nil
    end

    k.extension_id
  end

  # Get the string extension name for the specified extension ID.
  #
  # @param [Integer] id The ID of the extension to retrieve the name for.
  # @return [String, nil] The extension name or nil if the ID does not exist.
  def self.get_extension_name(id)
    id = id - (id % COMMAND_ID_RANGE)

    self.get_extension_names.find do |name|
      begin
        klass = self.get_extension_klass(name)
      rescue RuntimeError
        next
      end

      klass.extension_id == id
    end
  end

  # Get the module for the specified extension name.
  #
  # @param [String] name The name of the extension to retrieve the module for.
  #   This parameter is case insensitive.
  # @raise [RuntimeError] A RuntimeError is raised if the specified module can
  #   not be loaded.
  # @return [Module] The extension module.
  def self.get_extension_module(name)
    name.downcase!

    begin
      require("rex/post/meterpreter/extensions/#{name}/#{name}")
    rescue LoadError
      # the extension doesn't exist on disk
      raise RuntimeError, "Unable to load extension '#{name}' - module does not exist."
    end
    s = Rex::Post::Meterpreter::Extensions.constants.find { |c| name == c.to_s.downcase }
    Rex::Post::Meterpreter::Extensions.const_get(s)
  end

  # Get the class for the specified extension name.
  #
  # @param [String] name The name of the extension to retrieve the class for.
  #   This parameter is case insensitive.
  # @raise [RuntimeError] A RuntimeError is raised if the specified module can
  #   not be loaded.
  # @return [Class] The extension class.
  def self.get_extension_klass(name)
    name.downcase!

    unless @@klasses[name]
      mod = self.get_extension_module(name)
      @@klasses[name] = mod.const_get(mod.name.split('::').last)
    end

    @@klasses[name]
  end

  def self.dump_extensions
    self.get_extension_names.each { |n|
      STDERR.puts("EXTENSION_ID_#{n.upcase} = #{self.get_extension_id(n)}\n")
    }
  end

end

end
end
end
