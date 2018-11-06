module Enumerable
  def sum(accumulator = 0, &block)
    values = block_given? ? map(&block) : self
    values.inject(accumulator, :+)
  end unless method_defined? :sum
end
