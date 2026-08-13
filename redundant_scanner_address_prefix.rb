# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects a redundant target-address prefix (`#{rhost}`, `#{peer}`,
      # `#{rhost}:#{rport}`, `#{rhost}#{rport}`) at the start of a
      # `print_status`/`print_good`/`print_error`/`print_bad`/`print_line`
      # (and `vprint_*`) message, in modules that include
      # `Msf::Auxiliary::Scanner`.
      #
      # `Msf::Auxiliary::Scanner#peer` is already shown as a prefix on every
      # line printed while a scanner module's `run_host` is executing, so
      # repeating it manually at the start of a message produces duplicated
      # output, e.g.:
      #
      #   [*] 10.0.0.10:21          - 10.0.0.10:21 - Starting FTP login sweep
      #
      # This cop is deliberately scoped to `Msf::Auxiliary::Scanner` modules
      # only — the same interpolations are frequently necessary and NOT
      # redundant in other module types (e.g. `Msf::Post` modules, whose
      # output is never auto-prefixed with a peer/address).
      #
      # @example
      #   # bad
      #   print_status("#{rhost}:#{rport} - Starting scan")
      #   print_error("#{peer} - Connection failed")
      #   vprint_status("#{rhost} is running FooServer")
      #
      #   # good
      #   print_status("Starting scan")
      #   print_error("Connection failed")
      #   vprint_status("is running FooServer")
      class RedundantScannerAddressPrefix < Base
        extend AutoCorrector

        MSG = 'Remove redundant target-address prefix; ' \
              'Msf::Auxiliary::Scanner already prefixes printed output with the peer address.'

        PRINT_METHODS = %i[
          print_status print_good print_error print_bad print_line
          vprint_status vprint_good vprint_error vprint_bad vprint_line
        ].freeze

        ADDRESS_METHODS = %i[rhost peer].freeze

        def_node_matcher :bare_address_call?, <<~PATTERN
          (send nil? {#address_method?})
        PATTERN

        def on_send(node)
          return unless PRINT_METHODS.include?(node.method_name)
          return unless in_scanner_module?(node)

          first_arg = node.first_argument
          return unless first_arg&.dstr_type?

          strip_upto = redundant_prefix_end(first_arg)
          return unless strip_upto

          add_offense(first_arg) do |corrector|
            autocorrect(corrector, first_arg, strip_upto)
          end
        end

        private

        def address_method?(name)
          ADDRESS_METHODS.include?(name)
        end

        # Returns the index (exclusive) up to which children of the dstr
        # node form a redundant address prefix, or nil if there isn't one.
        def redundant_prefix_end(dstr)
          children = dstr.children
          return nil if children.empty?
          return nil unless interpolates_address?(children[0])

          idx = 1

          if interpolates?(children[0], :rhost)
            # #{rhost}:#{rport} or #{rhost}#{rport}
            if children[idx]&.str_type? && children[idx].value == ':' && interpolates?(children[idx + 1], :rport)
              idx += 2
            elsif interpolates?(children[idx], :rport)
              idx += 1
            end
          end

          # Require a separator (" - " or plain whitespace) or end-of-string
          # immediately after the address portion, so we don't strip an
          # address that's genuinely part of the sentence.
          next_child = children[idx]
          if next_child.nil?
            idx
          elsif next_child.str_type? && next_child.value.match?(/\A\s+(-\s+)?/)
            idx
          end
        end

        def interpolates_address?(node)
          ADDRESS_METHODS.any? { |m| interpolates?(node, m) }
        end

        def interpolates?(node, method_name)
          return false unless node&.begin_type? && node.children.one?

          inner = node.children.first
          inner&.send_type? && inner.method_name == method_name && inner.receiver.nil?
        end

        def in_scanner_module?(node)
          node.each_ancestor(:class).any? do |class_node|
            class_node.each_descendant(:send).any? do |send_node|
              send_node.method_name == :include && send_node.arguments.any? do |arg|
                arg.source.match?(/\bMsf::Auxiliary::Scanner\b/)
              end
            end
          end
        end

        def autocorrect(corrector, dstr, strip_upto)
          children = dstr.children
          first_removed = children[0]
          last_removed = children[strip_upto - 1]

          remaining = children[strip_upto..]
          if remaining && !remaining.empty? && remaining.first.str_type?
            # Strip the separator's leading whitespace/dash from the first
            # remaining string part too, so we don't leave a stray leading space.
            leftover = remaining.first.value.sub(/\A\s+(-\s+)?/, '')
            corrector.replace(remaining.first.loc.expression, leftover.inspect[1..-2])
          end

          corrector.remove(range_between(first_removed.loc.expression.begin_pos, last_removed.loc.expression.end_pos))
        end

        def range_between(start_pos, end_pos)
          Parser::Source::Range.new(processed_source.buffer, start_pos, end_pos)
        end
      end
    end
  end
end
