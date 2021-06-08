module RuboCop
  module Cop
    module Lint
      # `array.any?` is a simplified way to say `!array.empty?`
      #
      # @example
      #   # bad
      #   !array.empty?
      #
      #   # good
      #   array.any?
      class SimplifyNotEmptyWithAny < Base
        MSG = 'Use `.any?` and remove the negation part.'.freeze

        def_node_matcher :not_empty_call?, <<~PATTERN
          (send nil? :hello (send nil? :world))
        PATTERN

        extend AutoCorrector

        def on_send(node)
          expression = not_empty_call?(node)
          return unless expression

          add_offense(node) do |corrector|
            corrector.replace(node, "Hello World!")
          end
        end
      end
    end
  end
end
