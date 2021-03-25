# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class DeprecatedGemVersion < Base
        include RangeHelp
        extend AutoCorrector

        MSG = 'Use `Rex::Version` instead of `Gem::Version`.'

        # @!method gem_version_const(node)
        def_node_matcher :gem_version_const, <<~PATTERN
          (const
           $(const {nil? cbase} :Gem) {:Version})
        PATTERN

        # @!method gem_version_const_cbase(node)
        def_node_matcher :gem_version_const_cbase, <<~PATTERN
          (const
           $(const {cbase} :Gem) {:Version})
        PATTERN

        def on_const(node)
          return unless gem_version_const(node)

          add_offense(node, message: MSG) do |corrector|
            autocorrect(corrector, node)
          end
        end

        private

        def autocorrect(corrector, node)
          if gem_version_const_cbase(node)
            corrector.replace(gem_version_const_cbase(node), '::Rex')
          else
            corrector.replace(gem_version_const(node), 'Rex')
          end
        end

      end
    end
  end
end
