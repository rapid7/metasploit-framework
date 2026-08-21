# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Checks that modules with `Targets` defined do not redundantly specify
      # `Arch` or `Platform` at the top level of update_info when that
      # information is already present in all targets.
      #
      # The framework uses target-level Arch/Platform when present, falling
      # back to the module-level value only when the target does not specify
      # them (see `Msf::Exploit#target_arch` and `#target_platform`).
      # Therefore, specifying `Arch` or `Platform` at the top level is
      # redundant when every target already carries that information.
      #
      # @example
      #   # bad - Arch at top level when all targets define it
      #   update_info(
      #     info,
      #     'Arch' => ARCH_X86,
      #     'Targets' => [
      #       ['Windows', { 'Arch' => ARCH_X86 }]
      #     ]
      #   )
      #
      #   # bad - Platform at top level when all targets define it
      #   update_info(
      #     info,
      #     'Platform' => 'win',
      #     'Targets' => [
      #       ['Windows', { 'Platform' => 'win' }]
      #     ]
      #   )
      #
      #   # good - no top-level Arch/Platform when targets define them
      #   update_info(
      #     info,
      #     'Targets' => [
      #       ['Windows x86', { 'Platform' => 'win', 'Arch' => ARCH_X86 }],
      #       ['Windows x64', { 'Platform' => 'win', 'Arch' => ARCH_X64 }]
      #     ]
      #   )
      #
      #   # good - top-level Arch/Platform when targets don't define them
      #   update_info(
      #     info,
      #     'Arch' => ARCH_X86,
      #     'Platform' => 'win',
      #     'Targets' => [
      #       ['Automatic', {}]
      #     ]
      #   )
      class ModuleRedundantArchPlatform < Base
        extend AutoCorrector
        include RangeHelp

        MSG = 'Remove top-level `%s` as it is already defined in all `Targets`'

        CHECKED_KEYS = %w[Arch Platform].freeze

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          hash = update_info_node.arguments.find { |argument| hash_arg?(argument) }
          return if hash.nil?

          top_level_pairs = {}
          targets_node = nil

          hash.each_pair do |key, value|
            next unless key.type == :str

            if CHECKED_KEYS.include?(key.value)
              top_level_pairs[key.value] = hash.pairs.find { |pair| pair.key == key }
            elsif key.value == 'Targets'
              targets_node = value
            end
          end

          return if targets_node.nil?
          return if top_level_pairs.empty?
          return unless targets_node.type == :array

          targets = targets_node.children
          return if targets.empty?

          CHECKED_KEYS.each do |key_name|
            pair = top_level_pairs[key_name]
            next unless pair
            next unless all_targets_define_key?(targets, key_name)

            add_offense(pair.key, message: MSG % key_name) do |corrector|
              remove_pair_with_line(corrector, pair)
            end
          end
        end

        private

        # Checks whether every target in the Targets array defines the given key.
        # Each target is expected to be an array node like:
        #   ['Name', { 'Arch' => ..., 'Platform' => ... }]
        def all_targets_define_key?(targets, key_name)
          targets.all? do |target|
            next false unless target.type == :array

            target_hash = target.children.find { |child| hash_arg?(child) }
            next false if target_hash.nil?

            target_hash.pairs.any? do |pair|
              pair.key.type == :str && pair.key.value == key_name
            end
          end
        end

        def hash_arg?(node)
          node.type == :hash
        end

        # Removes a key-value pair and its entire line (leading whitespace,
        # trailing comma, and newline).
        def remove_pair_with_line(corrector, pair)
          range = pair.source_range
          end_pos = range.end_pos
          source = range.source_buffer.source

          # Consume trailing comma and whitespace/newline
          while end_pos < source.length && source[end_pos] =~ /[ \t]/
            end_pos += 1
          end
          if end_pos < source.length && source[end_pos] == ','
            end_pos += 1
          end
          while end_pos < source.length && source[end_pos] =~ /[ \t]/
            end_pos += 1
          end
          if end_pos < source.length && source[end_pos] == "\n"
            end_pos += 1
          end

          # Consume the leading whitespace on this line
          start_pos = range.begin_pos
          while start_pos > 0 && source[start_pos - 1] =~ /[ \t]/
            start_pos -= 1
          end

          removal_range = range.with(begin_pos: start_pos, end_pos: end_pos)
          corrector.remove(removal_range)
        end
      end
    end
  end
end
