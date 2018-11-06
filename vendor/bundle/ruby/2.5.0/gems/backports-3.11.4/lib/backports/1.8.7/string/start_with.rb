unless String.method_defined? :start_with?
  class String
    def start_with?(*prefixes)
      prefixes.any? do |prefix|
        if prefix.respond_to? :to_str
          prefix = prefix.to_str
          self[0, prefix.length] == prefix
        end
      end
    end
  end
end
