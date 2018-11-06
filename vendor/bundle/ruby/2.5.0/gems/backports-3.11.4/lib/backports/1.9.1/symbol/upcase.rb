unless Symbol.method_defined? :upcase
  class Symbol
    def upcase
      to_s.upcase.to_sym
    end
  end
end
