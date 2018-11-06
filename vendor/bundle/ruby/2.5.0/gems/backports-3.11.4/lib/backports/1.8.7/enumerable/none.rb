unless Enumerable.method_defined? :none?
  module Enumerable
    def none?(&block)
      !any?(&block)
    end
  end
end
