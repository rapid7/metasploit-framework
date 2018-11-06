unless Symbol.method_defined? :swapcase
  class Symbol
    def swapcase
      to_s.swapcase.to_sym
    end
  end
end
