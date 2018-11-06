unless Kernel.method_defined? :tap
  module Kernel
    def tap
      yield self
      self
    end
  end
end
