unless Integer.method_defined?(:div) || Fixnum.method_defined?(:div)
  class Fixnum
    def div(n)
      (self / n).to_i
    end
  end
end
