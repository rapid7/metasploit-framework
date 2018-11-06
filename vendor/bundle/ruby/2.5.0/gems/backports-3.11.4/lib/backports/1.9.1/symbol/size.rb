unless Symbol.method_defined? :size
  class Symbol
    def size
      to_s.size
    end
  end
end
