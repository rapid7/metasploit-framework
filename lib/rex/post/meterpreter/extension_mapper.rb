# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

class ExtensionMapper

  @@klasses = {}

  def self.get_extension_names
    base = ::File.join(File.dirname(__dir__), 'meterpreter/extensions')
    ::Dir.entries(base).select do |e|
      ::File.directory?(::File.join(base, e)) && !['.', '..'].include?(e)
    end
  end

  def self.get_extension_id(name)
    k = self.get_extension_klass(name)
    k.extension_id
  end

  def self.get_extension_name(id)
    self.get_extension_names.each do |name|
      begin
        klass = self.get_extension_klass(name)
      rescue RuntimeError
        next
      end
      return name if klass.extension_id == id
    end
  end

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
