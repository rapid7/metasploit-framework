unless Symbol.method_defined? :downcase
  class Symbol
    def downcase
      to_s.downcase.to_sym
    end
  end
end
