unless Kernel.method_defined? :public_send
  module Kernel
    def public_send(method, *args, &block)
      if respond_to?(method) && !protected_methods.include?(method.to_s)
        send(method, *args, &block)
      else
        :foo.generate_a_no_method_error_in_preparation_for_method_missing rescue nil
        # otherwise a NameError might be raised when we call method_missing ourselves
        method_missing(method.to_sym, *args, &block)
      end
    end
  end
end
