module Treetop
  module Runtime
    class CompiledParser
      include Treetop::Runtime

      attr_reader :input, :index, :max_terminal_failure_index
      attr_writer :root
      attr_accessor :consume_all_input
      alias :consume_all_input? :consume_all_input

      def initialize
        self.consume_all_input = true
      end

      def parse(input, options = {})
        prepare_to_parse(input)
        @index = options[:index] if options[:index]
        result = send("_nt_#{options[:root] || root}")
        should_consume_all = options.include?(:consume_all_input) ? options[:consume_all_input] : consume_all_input?
        return nil if (should_consume_all && index != input.size)
        return SyntaxNode.new(input, index...(index + 1)) if result == true
        return result
      end

      def failure_index
        max_terminal_failure_index
      end

      def failure_line
        @terminal_failures && input.line_of(failure_index)
      end

      def failure_column
        @terminal_failures && input.column_of(failure_index)
      end

      def failure_reason
        return nil unless (tf = terminal_failures) && tf.size > 0
        "Expected " +
          (tf.size == 1 ?
           tf[0].expected_string :
                 "one of #{tf.map{|f| f.expected_string}.uniq*', '}"
          ) +
                " at line #{failure_line}, column #{failure_column} (byte #{failure_index+1})" +
                " after #{input[index...failure_index]}"
      end

      def terminal_failures
        if @terminal_failures.empty? || @terminal_failures[0].is_a?(TerminalParseFailure)
          @terminal_failures
        else
          @terminal_failures.map! {|tf_ary| TerminalParseFailure.new(*tf_ary) }
        end
      end


      protected

      attr_reader :node_cache, :input_length
      attr_writer :index

      def prepare_to_parse(input)
        @input = input
        @input_length = input.length
        reset_index
        @node_cache = Hash.new {|hash, key| hash[key] = Hash.new}
        @regexps = {}
        @terminal_failures = []
        @max_terminal_failure_index = 0
      end

      def reset_index
        @index = 0
      end

      def parse_anything(node_class = SyntaxNode, inline_module = nil)
        if index < input.length
          result = instantiate_node(node_class,input, index...(index + 1))
          result.extend(inline_module) if inline_module
          @index += 1
          result
        else
          terminal_parse_failure("any character")
        end
      end

      def instantiate_node(node_type,*args)
        if node_type.respond_to? :new
          node_type.new(*args)
        else
          SyntaxNode.new(*args).extend(node_type)
        end
      end

      def has_terminal?(terminal, regex, index)
        if regex
          rx = @regexps[terminal] ||= Regexp.new(terminal)
          input.index(rx, index) == index
        else
          input[index, terminal.size] == terminal
        end
      end

      def terminal_parse_failure(expected_string)
        return nil if index < max_terminal_failure_index
        if index > max_terminal_failure_index
          @max_terminal_failure_index = index
          @terminal_failures = []
        end
        @terminal_failures << [index, expected_string]
        return nil
      end
    end
  end
end
