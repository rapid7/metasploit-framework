# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleDisclosureDatePresent < Base
        extend AutoCorrector
        include Alignment

        MSG = 'Module is missing the required DisclosureDate information'

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          return if node.source =~ /Generic Payload Handler/

          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          hash = update_info_node.arguments.find { |argument| hash_arg?(argument) }
          disclosure_date_present = false
          last_key = nil
          hash.each_pair do |key, _value|
            if key.value == 'DisclosureDate'
              disclosure_date_present = true
            end
            last_key = key
          end

          unless disclosure_date_present
            add_offense(last_key || hash)
          end
        end

        private

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
