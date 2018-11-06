unless String.method_defined? :delete_suffix
  require 'backports/tools/arguments'

  class String
    def delete_suffix(suffix)
      suffix = Backports.coerce_to_str(suffix)
      len = suffix.length
      if len > 0 && index(suffix, -len)
        self[0...-len]
      else
        dup
      end
    end
  end
end

unless String.method_defined? :delete_suffix!
  require 'backports/tools/arguments'

  class String
    def delete_suffix!(suffix)
      suffix = Backports.coerce_to_str(suffix)
      chomp! if frozen?
      len = suffix.length
      if len > 0 && index(suffix, -len)
        self[-len..-1] = ''
        self
      else
        nil
      end
    end
  end
end
