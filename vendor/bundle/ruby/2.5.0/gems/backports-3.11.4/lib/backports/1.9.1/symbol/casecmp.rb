unless Symbol.method_defined? :casecmp
  class Symbol
    def casecmp(with)
      return nil unless with.is_a? Symbol
      to_s.casecmp(with.to_s)
    end
  end
end
