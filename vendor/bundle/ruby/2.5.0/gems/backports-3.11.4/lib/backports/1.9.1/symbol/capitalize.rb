unless Symbol.method_defined? :capitalize
  class Symbol
    def capitalize
      to_s.capitalize.to_sym
    end
  end
end
