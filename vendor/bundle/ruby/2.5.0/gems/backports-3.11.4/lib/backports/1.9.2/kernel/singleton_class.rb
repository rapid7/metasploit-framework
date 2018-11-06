unless Kernel.method_defined? :singleton_class
  module Kernel
    def singleton_class
      class << self; self; end
    end
  end
end
