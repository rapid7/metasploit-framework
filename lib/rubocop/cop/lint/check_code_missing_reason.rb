# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects CheckCode usages inside `check` methods that are missing a
      # human-readable reason string.
      #
      # Every CheckCode *returned* from a `check` method should include a reason
      # so that users understand why the target was assessed that way. The cop
      # only fires inside `def check` bodies, which avoids false positives from
      # the many legitimate non-return uses of CheckCode constants elsewhere
      # (comparisons, case/when branches, array membership checks, etc.).
      #
      # Flagged patterns (inside `def check` only):
      # - Bare constants with no call:  `CheckCode::Safe`
      # - Empty calls:                  `CheckCode::Safe()`
      # - Kwargs-only calls:            `CheckCode::Safe(details: {...})`
      #
      # @example
      #   # bad - bare constant, no reason
      #   def check
      #     CheckCode::Safe
      #     Exploit::CheckCode::Vulnerable
      #   end
      #
      #   # bad - called with no reason string
      #   def check
      #     CheckCode::Safe()
      #     Exploit::CheckCode::Unknown()
      #   end
      #
      #   # bad - only keyword args, no reason string
      #   def check
      #     CheckCode::Vulnerable(details: { version: '1.0' })
      #   end
      #
      #   # good - reason string provided
      #   def check
      #     CheckCode::Safe('The target is not running the vulnerable service')
      #     Exploit::CheckCode::Appears("Version #{version} appears vulnerable")
      #     CheckCode::Vulnerable('Confirmed RCE', details: { version: version })
      #   end
      #
      #   # fine - comparisons and case/when outside check are not flagged
      #   def exploit
      #     fail_with(...) unless check == CheckCode::Vulnerable
      #     case checkcode
      #     when Exploit::CheckCode::Vulnerable, Exploit::CheckCode::Appears
      #       print_good(checkcode.message)
      #     end
      #   end
      #
      class CheckCodeMissingReason < Base
        MSG = 'Provide a human-readable reason string when returning a CheckCode, ' \
              "e.g. `%<check_code>s('The target is not vulnerable because ...')`"

        CHECK_CODE_METHODS = %i[
          Unknown
          Safe
          Detected
          Appears
          Vulnerable
          Unsupported
        ].to_set.freeze

        # Matches the receiver of a CheckCode call or constant — the `CheckCode`
        # portion of `CheckCode::Safe`, `Exploit::CheckCode::Safe`, or
        # `Msf::Exploit::CheckCode::Safe`.
        def_node_matcher :check_code_receiver?, <<~PATTERN
          {
            (const nil? :CheckCode)
            (const (const nil? :Exploit) :CheckCode)
            (const (const (const nil? :Msf) :Exploit) :CheckCode)
          }
        PATTERN

        # Matches a bare CheckCode constant with no call, e.g. `CheckCode::Safe`
        # or `Exploit::CheckCode::Appears`.
        def_node_matcher :bare_check_code_const?, <<~PATTERN
          (const #check_code_receiver? CHECK_CODE_METHODS)
        PATTERN

        # Matches a CheckCode method call, e.g. `CheckCode::Safe(...)` or
        # `Exploit::CheckCode::Appears('msg')`.
        def_node_matcher :check_code_call?, <<~PATTERN
          (send #check_code_receiver? CHECK_CODE_METHODS ...)
        PATTERN

        def on_const(node)
          return unless bare_check_code_const?(node)
          return unless inside_check_method?(node)
          # Skip if this const is the receiver of a send node — the on_send
          # handler will cover that case and we don't want a double offense.
          return if node.parent&.send_type? && node.parent.receiver == node
          # Skip when used as a comparator: `checkcode == CheckCode::Safe`,
          # `check.eql? CheckCode::Vulnerable`, case/when branches, arrays, etc.
          # These are consumers of a CheckCode value, not return values.
          return if used_as_comparator?(node)

          add_offense(node, message: format(MSG, check_code: node.source))
        end

        def on_send(node)
          return unless check_code_call?(node)
          return unless inside_check_method?(node)
          return if reason?(node)

          add_offense(node, message: format(MSG, check_code: "#{node.receiver.source}::#{node.method_name}"))
        end

        private

        # Returns true if the node is inside a `def check` method body.
        def inside_check_method?(node)
          node.each_ancestor(:def).any? { |def_node| def_node.method_name == :check }
        end

        COMPARISON_METHODS = %i[== != === =~ !~ eql? equal?].to_set.freeze

        # Returns true when the CheckCode constant is being used as a comparator
        # rather than as a return value — e.g. the RHS of `==`/`eql?`, a
        # case/when branch, or an array element.
        def used_as_comparator?(node)
          parent = node.parent
          return false unless parent

          # `when CheckCode::Safe` or `when CheckCode::Safe, CheckCode::Appears`
          return true if parent.when_type?

          # `[CheckCode::Vulnerable, CheckCode::Appears]`
          return true if parent.array_type?

          # `result == CheckCode::Safe`, `check.eql? CheckCode::Vulnerable`, etc.
          # The node must be an argument (not the receiver) of the comparison send.
          return true if parent.send_type? &&
                         parent.receiver != node &&
                         COMPARISON_METHODS.include?(parent.method_name)

          false
        end

        # Returns true if the call has a non-hash first positional argument —
        # i.e. any value used as the reason (string, interpolated string,
        # variable, exception object, method call result, etc.).
        # A hash as the sole first arg means only keyword args were passed.
        def reason?(node)
          first_arg = node.arguments.first
          return false if first_arg.nil?
          return false if first_arg.hash_type?

          true
        end
      end
    end
  end
end
