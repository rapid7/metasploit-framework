# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleInvalidDefaultTarget < Base
        extend AutoCorrector
        include Alignment

        MSG = 'Module DefaultTarget is out of range. Must specify a valid target index between 0 and %<targets>s'

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          hash = update_info_node.arguments.find { |argument| hash_arg?(argument) }

          targets = 0
          hash.each_pair do |key, value|
            next unless key.value == 'Targets'

            if value.array_type?
              targets = value.values.size
            end

            break
          end

          hash.each_pair do |key, value|
            next unless key.value == 'DefaultTarget'
            next if value.value < targets
            next if value.value == 0

            add_offense(
              value,
              message: format(MSG, targets: (targets - 1).to_s),
              &autocorrector(value)
            )

            break
          end
        end

        private

        def autocorrector(value_node)
          lambda do |corrector|
            corrector.replace(value_node.loc.expression, '0')
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
