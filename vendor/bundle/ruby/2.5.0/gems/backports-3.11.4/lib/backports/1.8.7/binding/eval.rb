unless Binding.method_defined? :eval
  class Binding
    def eval(expr, *arg)
      Kernel.eval(expr, self, *arg)
    end
  end
end
