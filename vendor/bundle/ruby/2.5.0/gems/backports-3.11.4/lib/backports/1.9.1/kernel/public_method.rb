unless Kernel.method_defined? :public_method
  module Kernel
    def public_method(meth)
      if respond_to?(meth) && !protected_methods.include?(meth.to_s)
        method(meth)
      else
        raise NameError, "undefined method `#{meth}' for class `#{self.class}'"
      end
    end
  end
end
