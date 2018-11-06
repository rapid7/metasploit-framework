unless Enumerable.method_defined? :slice_after
  require 'backports/tools/arguments'
  require 'backports/1.9.1/enumerator/new'

  module Enumerable
    def slice_after(pattern = Backports::Undefined, &block)
      raise ArgumentError, 'both pattern and block are given' if pattern != Backports::Undefined && block
      raise ArgumentError, 'wrong number of arguments (given 0, expected 1)' if pattern == Backports::Undefined && !block
      enum = self
      block ||= Proc.new{|elem| pattern === elem}
      Enumerator.new do |y|
        acc = []
        enum.each do |*elem|
          elem = elem.first if elem.length == 1
          acc << elem
          if block.call(elem)
            y.yield acc
            acc = []
          end
        end
        y.yield acc unless acc.empty?
      end
    end
  end
end
