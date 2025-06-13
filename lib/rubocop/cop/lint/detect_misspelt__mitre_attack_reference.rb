# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # This cop checks for misspelt ATT&CK references in module metadata
      # within the initialize method and autocorrects them to 'ATT&CK'.
      class DetectMisspeltMitreAttackReference < Base
        extend AutoCorrector

        MSG = "Mispelt ATT&CK reference. Use 'ATT&CK' instead."
        VALID = 'ATT&CK'
        # Misspellings to detect and correct
        MISSPELLINGS = %w[ATTACK AT&CK ATTK ATTCK ATT&C ATTAC ATT&K TT&CK TTACK]

        def on_def(node)
          return unless node.method_name == :initialize

          node.each_descendant(:array) do |array_node|
            parent = array_node.parent
            next unless parent&.pair_type? && parent.key.value == 'References'

            array_node.each_descendant(:array) do |ref_node|
              next unless ref_node.children.first&.str_type?

              ref_name = ref_node.children.first.value
              next unless MISSPELLINGS.include?(ref_name)

              add_offense(ref_node.children.first, message: MSG) do |corrector|
                corrector.replace(ref_node.children.first.loc.expression, "'#{VALID}'")
              end
            end
          end
        end
      end
    end
  end
end
