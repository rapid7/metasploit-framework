# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects usage of the legacy `HttpFingerprint` constant assignment.
      #
      # `HttpFingerprint` was a passive fingerprinting mechanism that predates
      # the modern `check` method API. Modules should implement a `check` method
      # and use `prepend Msf::Exploit::Remote::AutoCheck` instead.
      #
      # @example
      #   # bad - legacy passive fingerprinting
      #   HttpFingerprint = { :pattern => [/Apache/] }
      #
      #   # good - active check method
      #   prepend Msf::Exploit::Remote::AutoCheck
      #
      #   def check
      #     # version detection logic
      #     CheckCode::Appears('Target appears vulnerable')
      #   end
      #
      class ModuleHttpFingerprint < Base
        MSG = 'HttpFingerprint is a legacy passive fingerprinting mechanism. ' \
              'Implement a check method and prepend AutoCheck instead. ' \
              'See Modernizing Existing Modules in CONTRIBUTING.md.'

        def on_casgn(node)
          _scope, name, _value = *node
          return unless name == :HttpFingerprint

          add_offense(node, message: MSG)
        end
      end
    end
  end
end
