# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects modules that hardcode a PAYLOAD in DefaultOptions.
      #
      # The framework can automatically select the most appropriate payload based
      # on the target and available session types. Hardcoding a default payload
      # limits flexibility and may not work in all environments.
      #
      # If a module genuinely requires a specific payload (e.g. the framework's
      # auto-selection picks an incompatible one), suppress with an inline
      # `# rubocop:disable Lint/ModuleDefaultPayload` and add a comment explaining
      # why. This makes the workaround searchable so the underlying auto-selection
      # issue can be fixed later without blocking the PR.
      #
      # @example
      #   # bad - hardcoded default payload without justification
      #   'DefaultOptions' => {
      #     'PAYLOAD' => 'cmd/unix/reverse_bash'
      #   }
      #
      #   # good - let the framework choose
      #   'DefaultOptions' => {
      #     'SSL' => true,
      #     'WfsDelay' => 5
      #   }
      #
      #   # acceptable - justified workaround (searchable for future fix)
      #   'DefaultOptions' => {
      #     # Auto-selection picks generic/shell_reverse_tcp which lacks job support
      #     'PAYLOAD' => 'cmd/unix/reverse_bash' # rubocop:disable Lint/ModuleDefaultPayload
      #   }
      #
      class ModuleDefaultPayload < Base
        MSG = 'Do not hardcode a default PAYLOAD in DefaultOptions — ' \
              'let the framework choose automatically. ' \
              'If a specific payload is genuinely required, add a comment explaining why ' \
              'and suppress with `# rubocop:disable Lint/ModuleDefaultPayload`. ' \
              'See Modernizing Existing Modules in CONTRIBUTING.md.'

        def on_pair(node)
          return unless payload_in_default_options?(node)

          add_offense(node, message: MSG)
        end

        private

        # Check if this pair node is 'PAYLOAD' => ... inside a 'DefaultOptions' hash
        def payload_in_default_options?(node)
          # Node must be a pair with key 'PAYLOAD'
          return false unless node.key.str_type? && node.key.value == 'PAYLOAD'

          # Parent must be a hash
          parent_hash = node.parent
          return false unless parent_hash&.hash_type?

          # Grandparent must be a pair with key 'DefaultOptions'
          grandparent_pair = parent_hash.parent
          return false unless grandparent_pair&.pair_type?
          return false unless grandparent_pair.key.str_type? && grandparent_pair.key.value == 'DefaultOptions'

          true
        end
      end
    end
  end
end
