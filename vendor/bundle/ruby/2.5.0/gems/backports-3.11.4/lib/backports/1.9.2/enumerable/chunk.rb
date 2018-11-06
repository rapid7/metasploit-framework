unless Enumerable.method_defined? :chunk
  require 'backports/1.9.1/enumerator/new'

  module Enumerable
    def chunk(initial_state = nil, &original_block)
      raise ArgumentError, "no block given" unless block_given?
      ::Enumerator.new do |yielder|
        previous = nil
        accumulate = []
        block = initial_state.nil? ? original_block : Proc.new{|val| original_block.call(val, initial_state.clone)}
        each do |val|
          key = block.call(val)
          if key.nil? || (key.is_a?(Symbol) && key.to_s[0,1] == "_")
            yielder.yield [previous, accumulate] unless accumulate.empty?
            accumulate = []
            previous = nil
            case key
            when nil, :_separator
            when :_alone
              yielder.yield [key, [val]]
            else
              raise RuntimeError, "symbol beginning with an underscore are reserved"
            end
          else
            if previous.nil? || previous == key
              accumulate << val
            else
              yielder.yield [previous, accumulate] unless accumulate.empty?
              accumulate = [val]
            end
            previous = key
          end
        end
        # what to do in case of a break?
        yielder.yield [previous, accumulate] unless accumulate.empty?
      end
    end
  end
end
