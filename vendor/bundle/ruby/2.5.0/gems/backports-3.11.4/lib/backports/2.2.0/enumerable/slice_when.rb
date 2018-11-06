unless Enumerable.method_defined? :slice_when
  require 'backports/tools/arguments'
  require 'backports/1.9.1/enumerator/new'

  module Enumerable
    def slice_when(&block)
      raise ArgumentError, 'tried to create Proc object without a block' unless block
      enum = self
      Enumerator.new do |y|
        acc = []
        prev = Backports::Undefined
        enum.each do |*elem|
          elem = elem.first if elem.length == 1
          unless prev == Backports::Undefined
            if block.call(prev, elem)
              y.yield acc
              acc = []
            end
          end
          acc << elem
          prev = elem
        end
        y.yield acc unless acc.empty?
      end
    end
  end
end
