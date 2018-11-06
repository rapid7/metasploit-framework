unless Symbol.method_defined? :<=>
  class Symbol
    def <=>(with)
      return nil unless with.is_a? Symbol
      to_s <=> with.to_s
    end
  end
end
