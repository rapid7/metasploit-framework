# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleDisclosureDateFormat < Base
        include Alignment

        # 2020-01-03
        REQUIRED_DATE_FORMAT = '%Y-%m-%d'
        MSG = "Modules should specify a DisclosureDate with the required format '%<format>s', for example '%<example>s'"

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
          hash.each_pair do |key, value|
            next unless key.value == 'DisclosureDate'
            next if valid_disclosure_date?(value)

            add_offense(
              value,
              message: format(MSG, format: REQUIRED_DATE_FORMAT, example: DateTime.now.strftime(REQUIRED_DATE_FORMAT))
            )
          end
        end

        private

        def valid_disclosure_date?(value_node)
          value_node.type == :str && Date.strptime(value_node.value, REQUIRED_DATE_FORMAT)
        rescue StandardError
          false
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
