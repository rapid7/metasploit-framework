# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleDisclosureDateFormat < Base
        extend AutoCorrector
        include Alignment

        # 2020-01-03
        REQUIRED_DATE_FORMAT = '%Y-%m-%d'
        CORRECTABLE_DATE_FORMATS = [
          # Jan 3 2020
          '%b %d %Y',
        ].freeze
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
              message: format(MSG, format: REQUIRED_DATE_FORMAT, example: DateTime.now.strftime(REQUIRED_DATE_FORMAT)),
              &autocorrector(value)
            )
          end
        end

        private

        def autocorrector(value_node)
          return nil unless correctable_disclosure_date?(value_node)

          lambda do |corrector|
            corrector.replace(value_node.loc.expression, "'#{format_disclosure_date!(value_node)}'")
          end
        end

        def valid_disclosure_date?(value_node)
          value_node.type == :str && Date.strptime(value_node.value, REQUIRED_DATE_FORMAT)
        rescue StandardError
          false
        end

        def correctable_disclosure_date?(value_node)
          format_disclosure_date!(value_node)
        rescue StandardError
          false
        end

        def format_disclosure_date!(value_node)
          CORRECTABLE_DATE_FORMATS.map do |format|
            begin
              Date.strptime(value_node.value, format).strftime(REQUIRED_DATE_FORMAT)
            rescue StandardError
              nil
            end
          end.compact.first
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
