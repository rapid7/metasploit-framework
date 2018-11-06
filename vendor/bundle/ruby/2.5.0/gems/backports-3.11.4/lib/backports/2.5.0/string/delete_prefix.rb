unless String.method_defined? :delete_prefix
  require 'backports/tools/arguments'

  class String
    def delete_prefix(prefix)
      prefix = Backports.coerce_to_str(prefix)
      if rindex(prefix, 0)
        self[prefix.length..-1]
      else
        dup
      end
    end
  end
end

unless String.method_defined? :delete_prefix!
  require 'backports/tools/arguments'

  class String
    def delete_prefix!(prefix)
      prefix = Backports.coerce_to_str(prefix)
      chomp! if frozen?
      len = prefix.length
      if len > 0 && rindex(prefix, 0)
        self[0...prefix.length] = ''
        self
      else
        nil
      end
    end
  end
end
