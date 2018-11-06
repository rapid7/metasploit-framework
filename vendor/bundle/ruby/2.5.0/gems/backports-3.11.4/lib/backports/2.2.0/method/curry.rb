unless Method.method_defined? :curry
  require 'backports/1.9.1/proc/curry'

  class Method
    def curry(argc = nil)
      to_proc.curry(argc)
    end
  end
end
