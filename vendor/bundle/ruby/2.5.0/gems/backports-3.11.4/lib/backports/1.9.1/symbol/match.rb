unless Symbol.method_defined? :match
  class Symbol
    def match(with)
      to_s =~ with
    end

    alias_method :=~, :match
  end
end
