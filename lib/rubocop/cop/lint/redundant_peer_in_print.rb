# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Detects redundant host/port prefixes in print_status, print_error, print_good,
      # print_warning, print_bad, vprint_status, vprint_error, vprint_good, vprint_warning,
      # and vprint_bad calls.
      #
      # The framework's `print_prefix` (from Msf::Exploit::Remote::Tcp and the scanner mixin)
      # already prepends `peer` (host:port) to console output. Manually including `#{peer}`,
      # `#{rhost}:#{rport}`, `#{ip}:#{rport}`, `#{Rex::Socket.to_authority(rhost, rport)}`,
      # `#{target_host}`, `#{rhost}`, or `#{ip}` at the start of the message produces
      # duplicated address information.
      #
      # @example
      #   # bad
      #   print_status("#{peer} - Starting scan")
      #   print_error("#{rhost}:#{rport} - Connection failed")
      #   vprint_status("#{Rex::Socket.to_authority(rhost, rport)} - Sending request")
      #   print_good("#{target_host} - Detected WordPress")
      #   vprint_error("#{ip} seems to be down")
      #   print_error("#{rhost} - Communication error")
      #
      #   # good
      #   print_status("Starting scan")
      #   print_error("Connection failed")
      #   vprint_status("Sending request")
      #   print_good("Detected WordPress")
      #   vprint_error("seems to be down")
      #   print_error("Communication error")
      class RedundantPeerInPrint < Base
        extend AutoCorrector

        MSG = 'Redundant peer/host prefix in print message. The framework auto-prepends ' \
              'host:port via `print_prefix` -- see CONTRIBUTING.md.'

        PRINT_METHODS = %i[
          print_status print_error print_good print_warning print_bad
          vprint_status vprint_error vprint_good vprint_warning vprint_bad
        ].freeze

        # Separator patterns stripped from the source text following the prefix.
        # Matches raw source chars (e.g. space-dash-space or leading space).
        SOURCE_SEPARATOR_PATTERN = /\A( - | )/

        def on_send(node)
          return unless PRINT_METHODS.include?(node.method_name)

          arg = node.first_argument
          return unless arg
          return unless arg.dstr_type?

          prefix_end_index = detect_prefix(arg)
          return unless prefix_end_index

          add_offense(node) do |corrector|
            correct_prefix(corrector, arg, prefix_end_index)
          end
        end

        private

        # Returns the index into dstr.children AFTER the prefix nodes,
        # or nil if no prefix is detected.
        def detect_prefix(dstr)
          children = dstr.children
          return nil if children.empty?

          first = children[0]

          # Pattern 1: "#{peer}..." at the start
          return 1 if peer_interpolation?(first)

          # Pattern 2: "#{Rex::Socket.to_authority(rhost, rport)}..." at the start
          return 1 if to_authority_interpolation?(first)

          # Pattern 3: "#{rhost}:#{rport}..." or "#{ip}:#{rport}..." at the start
          if children.length >= 3 &&
             host_like_interpolation?(children[0]) &&
             colon_separator?(children[1]) &&
             port_like_interpolation?(children[2])
            return 3
          end

          # Pattern 4: "#{target_host}..." at the start
          return 1 if target_host_interpolation?(first)

          # Pattern 5: "#{rhost}..." or "#{ip}..." standalone (without :port)
          return 1 if standalone_host_interpolation?(first)

          nil
        end

        # Remove prefix nodes and any leading separator from the remaining string.
        # Operates on raw source text to preserve escape sequences (\n, \t, etc.).
        def correct_prefix(corrector, dstr, prefix_end_index)
          children = dstr.children

          prefix_start = children[0].loc.expression.begin_pos
          remaining_child = children[prefix_end_index]

          if remaining_child.nil?
            # Prefix is the entire string content -- remove it all
            prefix_end = children.last.loc.expression.end_pos
            range = Parser::Source::Range.new(dstr.loc.expression.source_buffer, prefix_start, prefix_end)
            corrector.remove(range)
          elsif remaining_child.str_type?
            # Strip separator from the raw source text (preserves \n, \t, etc.)
            source_text = remaining_child.loc.expression.source
            trimmed = source_text.sub(SOURCE_SEPARATOR_PATTERN, '')

            # Remove prefix nodes + the original str source, replace with trimmed
            remaining_end = remaining_child.loc.expression.end_pos
            range = Parser::Source::Range.new(dstr.loc.expression.source_buffer, prefix_start, remaining_end)
            corrector.replace(range, trimmed)
          else
            # Next piece is another interpolation -- just remove the prefix nodes
            prefix_end = remaining_child.loc.expression.begin_pos
            range = Parser::Source::Range.new(dstr.loc.expression.source_buffer, prefix_start, prefix_end)
            corrector.remove(range)
          end
        end

        # #{peer}
        def peer_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          inner.send_type? && inner.method_name == :peer && inner.receiver.nil?
        end

        # #{Rex::Socket.to_authority(rhost, rport)}
        def to_authority_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          return false unless inner.send_type? && inner.method_name == :to_authority

          receiver = inner.receiver
          return false unless receiver

          # Rex::Socket
          receiver.const_type? &&
            receiver.children[1] == :Socket &&
            receiver.children[0]&.const_type? &&
            receiver.children[0].children[1] == :Rex
        end

        # #{rhost} or #{ip} or #{target_host} -- used for composite host:port pattern
        def host_like_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          return false unless inner.send_type? && inner.receiver.nil?

          %i[rhost ip target_host].include?(inner.method_name)
        end

        # ":" literal string between host and port interpolations
        def colon_separator?(node)
          node.str_type? && node.value == ':'
        end

        # #{rport}
        def port_like_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          inner.send_type? && inner.method_name == :rport && inner.receiver.nil?
        end

        # #{target_host} alone at the start (common in scanner modules)
        def target_host_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          return false unless inner.send_type? && inner.receiver.nil?

          inner.method_name == :target_host
        end

        # #{rhost} or #{ip} standalone (without following :#{rport})
        def standalone_host_interpolation?(node)
          return false unless node.begin_type? && node.children.length == 1

          inner = node.children[0]
          return false unless inner.send_type? && inner.receiver.nil?

          %i[rhost ip].include?(inner.method_name)
        end
      end
    end
  end
end
