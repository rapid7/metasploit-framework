unless Symbol.method_defined? :empty?
  class Symbol
    def empty?
      to_s.empty?
    end
  end
end
