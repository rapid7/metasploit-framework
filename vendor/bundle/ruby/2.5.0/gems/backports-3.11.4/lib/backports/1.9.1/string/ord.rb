unless String.method_defined? :ord
  class String
    def ord
      codepoints.first or raise ArgumentError, "empty string"
    end
  end
end
