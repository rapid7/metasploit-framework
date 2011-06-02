module RKelly
  module Visitors
    class PointcutVisitor < Visitor
      attr_reader :matches
      def initialize(pattern, matches = [])
        @pattern  = pattern
        @matches  = matches
      end

      def >(pattern)
        pattern =
          case pattern
          when Class
            pattern.new(Object)
          else
            pattern
          end
        self.class.new(nil, @matches.map do |m|
          m.pointcut(pattern).matches
        end.flatten)
      end

      ALL_NODES.each do |type|
        define_method(:"visit_#{type}Node") do |o|
          @matches << o if @pattern === o
          super(o)
        end
      end
    end
  end
end
