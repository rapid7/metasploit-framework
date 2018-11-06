unless Array.method_defined? :dig
  class Array
    def dig(index, *rest)
      val = self[index]
      return val if rest.empty? || val == nil
      raise TypeError, "#{val.class} does not have #dig method" unless val.respond_to? :dig
      val.dig(*rest)
    end
  end
end
