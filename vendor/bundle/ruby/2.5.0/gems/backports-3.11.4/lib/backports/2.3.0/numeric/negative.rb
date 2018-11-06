unless Numeric.method_defined? :negative?
  class Numeric
    def negative?
      self < 0
    end
  end
end
