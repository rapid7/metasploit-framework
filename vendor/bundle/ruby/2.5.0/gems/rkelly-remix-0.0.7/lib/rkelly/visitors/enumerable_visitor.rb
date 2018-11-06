module RKelly
  module Visitors
    class EnumerableVisitor < Visitor
      def initialize(block)
        @block = block
      end

      ALL_NODES.each do |type|
        eval <<-RUBY
          def visit_#{type}Node(o)
            @block[o]
            super
          end
        RUBY
      end
    end
  end
end
