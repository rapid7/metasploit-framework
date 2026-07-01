# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      # Checks that modules with `Targets` defined do not redundantly specify
      # `Arch` or `Platform` at the top level of update_info when that
      # information is already present in all targets.
      #
      # The framework merges target metadata into the module metadata, so
      # specifying `Arch` or `Platform` at the top level is redundant when
      # every target already carries that information.
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

        REDUNDANT_ARCH_MSG = 'Remove top-level `Arch` as it is already defined in all `Targets`'
        REDUNDANT_PLATFORM_MSG = 'Remove top-level `Platform` as it is already defined in all `Targets`'

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def on_def(node)
          update_info_node = find_update_info_node(node) || find_nested_update_info_node(node)
          return if update_info_node.nil?

          hash = update_info_node.arguments.find { |argument| argument.type == :hash }
          return if hash.nil?

          top_level_keys = {}
          targets_node = nil

          hash.each_pair do |key, value|
            next unless key.type == :str

            case key.value
            when 'Arch', 'Platform'
              top_level_keys[key.value] = key
            when 'Targets'
              targets_node = value
            end
          end

          # Only flag if both Targets and the key exist at the top level
          return if targets_node.nil?
          return if top_level_keys.empty?

          # Targets should be an array of arrays
          return unless targets_node.type == :array

          targets = targets_node.children
          return if targets.empty?

          if top_level_keys.key?('Arch') && all_targets_define_key?(targets, 'Arch')
            add_offense(top_level_keys['Arch'], message: REDUNDANT_ARCH_MSG)
          end

          if top_level_keys.key?('Platform') && all_targets_define_key?(targets, 'Platform')
            add_offense(top_level_keys['Platform'], message: REDUNDANT_PLATFORM_MSG)
          end
        end

        private

        # Checks whether every target in the Targets array defines the given key.
        # Each target is expected to be an array node like:
        #   ['Name', { 'Arch' => ..., 'Platform' => ... }]
        def all_targets_define_key?(targets, key_name)
          targets.all? do |target|
            next false unless target.type == :array

            target_hash = target.children.find { |child| child.type == :hash }
            next false if target_hash.nil?

            target_hash.pairs.any? do |pair|
              pair.key.type == :str && pair.key.value == key_name
            end
          end
        end
      end
    end
  end
end
