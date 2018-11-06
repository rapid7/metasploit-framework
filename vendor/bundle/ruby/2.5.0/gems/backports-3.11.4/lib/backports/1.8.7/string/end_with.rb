unless String.method_defined? :end_with?
  class String
    def end_with?(*suffixes)
      suffixes.any? do |suffix|
        if suffix.respond_to? :to_str
          suffix = suffix.to_str
          self[-suffix.length, suffix.length] == suffix
        end
      end
    end
  end
end
