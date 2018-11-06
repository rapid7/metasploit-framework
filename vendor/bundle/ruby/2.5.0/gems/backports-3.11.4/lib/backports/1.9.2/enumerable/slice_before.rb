unless Enumerable.method_defined? :slice_before
  require 'backports/tools/arguments'
  require 'backports/1.9.1/enumerator/new'

  module Enumerable
    def slice_before(arg = Backports::Undefined, &block)
      if block_given?
        has_init = !(arg.equal? Backports::Undefined)
      else
        raise ArgumentError, "wrong number of arguments (0 for 1)" if arg.equal? Backports::Undefined
        block = Proc.new{|elem| arg === elem }
      end
      Enumerator.new do |yielder|
        init = arg.dup if has_init
        accumulator = nil
        each do |elem|
          start_new = has_init ? block.call(elem, init) : block.call(elem)
          if start_new
            yielder.yield accumulator if accumulator
            accumulator = [elem]
          else
            accumulator ||= []
            accumulator << elem
          end
        end
        yielder.yield accumulator if accumulator
      end
    end
  end
end
