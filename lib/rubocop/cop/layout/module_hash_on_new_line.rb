module RuboCop
  module Cop
    module Layout
      class ModuleHashOnNewLine < Base
        extend AutoCorrector
        include Alignment

        MSG = "%<name>s should start on its own line"
        MISSING_NEW_LINE_MSG = "A new line is missing"

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          unless begins_its_line?(update_info_node.source_range)
            add_offense(update_info_node.loc.begin, message: message(update_info_node), &autocorrector(update_info_node))
          end

          # Ensure every argument to update_info is on its own line, i.e. info and the hash arguments
          update_info_node.arguments.each do |argument|
            unless begins_its_line?(argument.source_range)
              add_offense(argument.source_range, message: message(argument), &autocorrector(argument))
            end
          end

          if missing_new_line_after_parenthesis?(update_info_node)
            add_offense(update_info_node.loc.end, message: MISSING_NEW_LINE_MSG, &autocorrector(update_info_node))
          end
        end

        private

        def autocorrector(node)
          lambda do |corrector|
            if merge_function?(node) && missing_new_line_after_parenthesis?(node)
              # Ensure there's always a new line after `update_info(...)` to avoid `))` at the end of the `super(update_info` call
              corrector.replace(node.source_range.end, "\n#{offset(node.parent)}")
            else
              # Force a new line, and indent to the parent node. Other Layout rules will correct the positioning.
              corrector.replace(node.source_range, "\n#{indentation(node.parent)}#{node.source}")
            end
          end
        end

        def message(node)
          if update_info?(node)
            format(MSG, name: :update_info)
          elsif merge_info?(node)
            format(MSG, name: :merge_info)
          elsif info_arg?(node)
            format(MSG, name: :info)
          else
            format(MSG, name: :argument)
          end
        end

        def merge_function?(node)
          update_info?(node) || merge_info?(node)
        end

        def update_info?(node)
          node.type == :send && node.method_name == :update_info
        end

        def merge_info?(node)
          node.type == :send && node.method_name == :merge_info
        end

        def info_arg?(node)
          node.type == :lvar && node.children[0] == :info
        end

        def missing_new_line_after_parenthesis?(update_info_node)
          super_call = update_info_node.parent
          super_call.source.end_with? '))'
        end
      end
    end
  end
end
