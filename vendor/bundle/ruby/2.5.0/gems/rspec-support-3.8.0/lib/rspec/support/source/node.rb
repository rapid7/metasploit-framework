RSpec::Support.require_rspec_support 'source/location'

module RSpec
  module Support
    class Source
      # @private
      # A wrapper for Ripper AST node which is generated with `Ripper.sexp`.
      class Node
        include Enumerable

        attr_reader :sexp, :parent

        def self.sexp?(array)
          array.is_a?(Array) && array.first.is_a?(Symbol)
        end

        def initialize(ripper_sexp, parent=nil)
          @sexp = ripper_sexp.freeze
          @parent = parent
        end

        def type
          sexp[0]
        end

        def args
          @args ||= raw_args.map do |raw_arg|
            if Node.sexp?(raw_arg)
              Node.new(raw_arg, self)
            elsif Location.location?(raw_arg)
              Location.new(*raw_arg)
            elsif raw_arg.is_a?(Array)
              ExpressionSequenceNode.new(raw_arg, self)
            else
              raw_arg
            end
          end.freeze
        end

        def children
          @children ||= args.select { |arg| arg.is_a?(Node) }.freeze
        end

        def location
          @location ||= args.find { |arg| arg.is_a?(Location) }
        end

        # We use a loop here (instead of recursion) to prevent SystemStackError
        def each
          return to_enum(__method__) unless block_given?

          node_queue = []
          node_queue << self

          while (current_node = node_queue.shift)
            yield current_node
            node_queue.concat(current_node.children)
          end
        end

        def each_ancestor
          return to_enum(__method__) unless block_given?

          current_node = self

          while (current_node = current_node.parent)
            yield current_node
          end
        end

        def inspect
          "#<#{self.class} #{type}>"
        end

      private

        def raw_args
          sexp[1..-1] || []
        end
      end

      # @private
      # Basically `Ripper.sexp` generates arrays whose first element is a symbol (type of sexp),
      # but it exceptionally generates typeless arrays for expression sequence:
      #
      # Ripper.sexp('foo; bar')
      # => [
      #      :program,
      #      [ # Typeless array
      #        [:vcall, [:@ident, "foo", [1, 0]]],
      #        [:vcall, [:@ident, "bar", [1, 5]]]
      #      ]
      #    ]
      #
      # We wrap typeless arrays in this pseudo type node
      # so that it can be handled in the same way as other type node.
      class ExpressionSequenceNode < Node
        def type
          :_expression_sequence
        end

      private

        def raw_args
          sexp
        end
      end
    end
  end
end
