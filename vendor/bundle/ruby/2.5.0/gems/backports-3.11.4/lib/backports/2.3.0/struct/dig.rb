unless Struct.method_defined? :dig
  class Struct
    def dig(key, *rest)
      return nil unless respond_to?(key)
      val = self.public_send(key)
      return val if rest.empty? || val == nil
      raise TypeError, "#{val.class} does not have #dig method" unless val.respond_to? :dig
      val.dig(*rest)
    end
  end
end

