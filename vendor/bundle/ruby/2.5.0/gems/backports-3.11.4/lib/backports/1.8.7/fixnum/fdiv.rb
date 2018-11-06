unless Integer.method_defined?(:fdiv) || Fixnum.method_defined?(:fdiv)
  class Fixnum
    def fdiv(n)
      to_f / n
    end
  end
end
