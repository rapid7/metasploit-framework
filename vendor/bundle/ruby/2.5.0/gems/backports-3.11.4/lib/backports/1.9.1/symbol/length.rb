unless Symbol.method_defined? :length
  class Symbol
    def length
      to_s.length
    end
  end
end
