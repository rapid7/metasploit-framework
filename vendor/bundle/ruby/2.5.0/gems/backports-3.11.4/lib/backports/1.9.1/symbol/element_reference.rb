unless Symbol.method_defined? :[]
  class Symbol
    def [](*args)
      to_s[*args]
    end
  end
end
