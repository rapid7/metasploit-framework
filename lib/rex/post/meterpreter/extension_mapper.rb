# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

class ExtensionMapper

  @@klasses = {}

  def self.get_extension_id(name)
    k = self.get_extension_klass(name)
    k.extension_id
  end

  def self.get_extension_klass(name)
    name.downcase!

    unless @@klasses[name]
      begin
        require("rex/post/meterpreter/extensions/#{name}/#{name}")
      rescue LoadError
        # the extension doesn't exist on disk
        raise RuntimeError, "Unable to load extension '#{name}' - module does not exist."
      end
      s = Rex::Post::Meterpreter::Extensions.constants.select { |c|
        name == c.to_s.downcase
      }[0]
      @@klasses[name] =  Rex::Post::Meterpreter::Extensions.const_get(s).const_get(s)
    end

    @@klasses[name]
  end

  def self.dump_extensions
    base = ::File.join(File.dirname(__dir__), 'meterpreter/extensions')
    names = ::Dir.entries(base).select { |e|
      ::File.directory?(::File.join(base, e)) && !['.', '..'].include?(e)
    }
    names.each { |n|
      STDERR.puts("EXTENSION_ID_#{n.upcase} = #{self.get_extension_id(n)}\n")
    }
  end

end

end
end
end
