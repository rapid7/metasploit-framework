module Treetop
  module Compiler
    class ParsingExpression < Runtime::SyntaxNode
      attr_reader :address, :builder, :subexpression_address, :var_symbols, :parent_expression
    
      def compile(address, builder, parent_expression)
        @address = address
        @builder = builder
        @parent_expression = parent_expression
      end
      
      def node_class_name
        parent_expression && parent_expression.node_class_name || 'SyntaxNode'
      end
      
      def declared_module_name
        parent_expression && parent_expression.node_class_name
      end
      
      def inline_module_name
        parent_expression && parent_expression.inline_module_name
      end
      
      def decorated?
        parent_expression && (parent_expression.node_class_name || parent_expression.node_class_name || parent_expression.inline_module_name)
      end
      
      def optional_arg(arg)
        if arg
          ", #{arg}"
        else
          ''
        end
      end
    
      def use_vars(*var_symbols)
        @var_symbols = var_symbols
        builder << var_initialization
      end
    
      def result_var
        var(:result)
      end
    
      def accumulator_var
        var(:accumulator)
      end
      
      def start_index_var
        var(:start_index)
      end
    
      def subexpression_result_var
        "r#{subexpression_address}"
      end
    
      def subexpression_success?
        subexpression_result_var
      end
    
      def obtain_new_subexpression_address
        @subexpression_address = builder.next_address
      end
        
      def accumulate_subexpression_result
        builder.accumulate accumulator_var, subexpression_result_var
      end
    
      def assign_result(value_ruby)
        builder.assign result_var, value_ruby
      end
      
      def extend_result(module_name)
        builder.extend result_var, module_name
      end

      def extend_result_with_declared_module
        extend_result declared_module_name if declared_module_name
      end
      
      def extend_result_with_inline_module
        extend_result inline_module_name if inline_module_name
      end
    
      def reset_index
        builder.assign '@index', start_index_var
      end
      
      def epsilon_node
        "instantiate_node(SyntaxNode,input, index...index)"
      end
      
      def assign_failure(start_index_var)
        assign_result("nil")
      end
      
      def assign_lazily_instantiated_node
        assign_result("true")
      end
    
      def var_initialization
        left, right = [], []
        var_symbols.each do |symbol|
          if init_value(symbol)
            left << var(symbol)
            right << init_value(symbol)
          end
        end
        if left.empty?
          ""
        else
          left.join(', ') + ' = ' + right.join(', ')
        end
      end
    
      def var(var_symbol)
        case var_symbol
        when :result then "r#{address}"
        when :accumulator then "s#{address}"
        when :start_index then "i#{address}"
        else raise "Unknown var symbol #{var_symbol}."
        end
      end
    
      def init_value(var_symbol)
        case var_symbol
        when :accumulator then '[]'
        when :start_index then 'index'
        else nil
        end
      end
      
      def begin_comment(expression)
        #builder << "# begin #{on_one_line(expression)}"
      end
      
      def end_comment(expression)
        #builder << "# end #{on_one_line(expression)}"
      end
      
      def on_one_line(expression)
        expression.text_value.tr("\n", ' ')
      end
    end
  end
end
