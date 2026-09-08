# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects exploit modules that do not declare an explicit `Rank`.
      #
      # A module with no `Rank` silently defaults to `NormalRanking` at load time, so a
      # missing rank never fails to load and is easy to ship without ever choosing one.
      # Every exploit should state its reliability explicitly. Choose a value from
      # lib/msf/core/constants.rb (ManualRanking through ExcellentRanking).
      #
      # @example
      #   # bad - no Rank declared (silently defaults to NormalRanking)
      #   class MetasploitModule < Msf::Exploit::Remote
      #     def initialize(info = {})
      #       super
      #     end
      #   end
      #
      #   # good - explicit Rank
      #   class MetasploitModule < Msf::Exploit::Remote
      #     Rank = GreatRanking
      #
      #     def initialize(info = {})
      #       super
      #     end
      #   end
      #
      class ModuleMissingRank < Base
        MSG = 'Module does not declare an explicit Rank (it will silently default to NormalRanking). ' \
              'Add `Rank = <value>` using a value from lib/msf/core/constants.rb (ManualRanking through ExcellentRanking).'

        def on_class(node)
          # Only flag the MetasploitModule class, not nested helper/utility classes
          return unless metasploit_module_class?(node)

          return if rank_declared?(node)

          add_offense(node, message: MSG)
        end

        private

        # The framework loader requires the primary module class be named MetasploitModule
        def metasploit_module_class?(class_node)
          class_node.identifier.short_name == :MetasploitModule
        end

        # Search the class body for a `Rank = ...` constant assignment
        def rank_declared?(class_node)
          class_node.each_descendant(:casgn).any? do |casgn_node|
            # casgn children: [namespace, :ConstName, value]
            casgn_node.children[1] == :Rank
          end
        end
      end
    end
  end
end
