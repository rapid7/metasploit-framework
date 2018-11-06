unless Symbol.method_defined? :succ
  class Symbol
    def succ
      to_s.succ.to_sym
    end
    alias_method :next, :succ
  end
end
