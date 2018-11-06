module Kernel
  def yield_self
    return to_enum(__method__) { 1 } unless block_given?
    yield self
  end unless method_defined? :yield_self
end
