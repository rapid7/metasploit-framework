# -*- coding: binary -*-

module Rex
module Post
module Meterpreter

class ExtensionMapper

  @@klasses = {}

  def self.get_extension_id(name)
    k = self.get_extension_klass(name)
    k.id
  end

  def self.get_extension_klass(name)
    name.capitalize!

    unless @@klasses[name]
      require("rex/post/meterpreter/extensions/#{name.downcase}/#{name.downcase}")
      s = name.to_sym
      @@klasses[name] =  Rex::Post::Meterpreter::Extensions.const_get(s).const_get(s)
    end

    @@klasses[name.downcase]
  end

end

end
end
end
