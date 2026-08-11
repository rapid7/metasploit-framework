# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects exploit and auxiliary modules that define a `check` method but do not
      # `prepend Msf::Exploit::Remote::AutoCheck`.
      #
      # AutoCheck wraps the `exploit`/`run` method to automatically call `check` before
      # exploitation, giving users the ability to verify vulnerability first.
      #
      # @example
      #   # bad - check method without AutoCheck prepend
      #   class MetasploitModule < Msf::Exploit::Remote
      #     include Msf::Exploit::Remote::HttpClient
      #
      #     def check
      #       CheckCode::Safe('Not vulnerable')
      #     end
      #
      #     def exploit
      #     end
      #   end
      #
      #   # good - AutoCheck prepended after includes
      #   class MetasploitModule < Msf::Exploit::Remote
      #     include Msf::Exploit::Remote::HttpClient
      #     prepend Msf::Exploit::Remote::AutoCheck
      #
      #     def check
      #       CheckCode::Safe('Not vulnerable')
      #     end
      #
      #     def exploit
      #     end
      #   end
      #
      class ModuleMissingAutocheck < Base
        MSG = 'Module has a check method but does not prepend Msf::Exploit::Remote::AutoCheck. ' \
              'Add it after your includes — see Modernizing Existing Modules in CONTRIBUTING.md.'

        def on_def(node)
          return unless node.method_name == :check

          class_node = node.each_ancestor(:class).first
          return unless class_node

          return if has_autocheck_prepend?(class_node)

          add_offense(node, message: MSG)
        end

        private

        # Search the class body for a `prepend` call whose argument ends in ::AutoCheck
        def has_autocheck_prepend?(class_node)
          class_node.each_descendant(:send).any? do |send_node|
            next unless send_node.method_name == :prepend
            next if send_node.arguments.empty?

            arg = send_node.first_argument
            const_ends_with_autocheck?(arg)
          end
        end

        # Check if a const node's name chain ends with :AutoCheck
        def const_ends_with_autocheck?(node)
          return false unless node&.const_type?

          node.short_name == :AutoCheck
        end
      end
    end
  end
end
