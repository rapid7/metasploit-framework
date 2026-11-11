# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Requires DefangedMode options to explain the module-specific risk they
      # prevent. A generic description does not help an operator decide whether
      # it is appropriate to disable the safety gate.
      #
      # Dynamic descriptions are left for review. This cop does not evaluate Ruby
      # or check the paired Markdown; document the same risk under the option's
      # heading in the module documentation.
      #
      # @example
      #   # bad
      #   OptBool.new('DefangedMode', [true, 'Run in defanged mode', true])
      #
      #   # good
      #   OptBool.new('DefangedMode', [true, 'Block exploitation that permanently changes the root password', true])
      class ModuleDefangedModeDescription < Base
        MSG = 'Explain the module-specific risk prevented by defanged mode in the option description.'
        RESTRICT_ON_SEND = [:new].freeze
        OPTION_CLASSES = %w[OptBool OptString Msf::OptBool Msf::OptString].freeze
        OPTION_NAMES = %w[DefangedMode DEFANGED_MODE].freeze
        UNKNOWN_DESCRIPTION = Object.new.freeze

        # @param node [RuboCop::AST::SendNode] an option constructor
        # @return [void]
        def on_send(node)
          return unless node.receiver&.const_type?
          return unless OPTION_CLASSES.include?(node.receiver.const_name.delete_prefix('::'))
          return unless node.first_argument&.str_type? && OPTION_NAMES.include?(node.first_argument.value)

          description = option_description(node)
          return if description.equal?(UNKNOWN_DESCRIPTION)
          return unless invalid_description?(description)

          add_offense(description || node)
        end

        private

        def option_description(node)
          attributes = node.arguments[1]
          keywords = node.last_argument if node.last_argument&.hash_type?
          attributes = nil if attributes == keywords

          return keyword_description(keywords) unless attributes
          return attributes if attributes.str_type? || attributes.dstr_type?
          return UNKNOWN_DESCRIPTION unless attributes.array_type?
          return UNKNOWN_DESCRIPTION if attributes.values.any?(&:splat_type?)

          description = attributes.values[1]
          return description if description && !description.nil_type? && !description.false_type?

          # OptBase falls back to desc: only when the array entry is nil/false.
          # An empty string still overrides desc: and must be reported.
          keyword_description(keywords) || description
        end

        def keyword_description(keywords)
          return unless keywords
          return UNKNOWN_DESCRIPTION if keywords.children.any?(&:kwsplat_type?)

          keywords.pairs.reverse.find { |pair| pair.key.sym_type? && pair.key.value == :desc }&.value
        end

        def invalid_description?(description)
          return true if description.nil? || description.nil_type? || description.false_type?
          return false unless description.str_type?

          normalized = description.value.downcase.gsub(/[[:space:]]+/, ' ').strip
          return true if normalized.empty?

          normalized.sub(/[[:punct:]]+\z/, '').rstrip == 'run in defanged mode'
        end
      end
    end
  end
end
