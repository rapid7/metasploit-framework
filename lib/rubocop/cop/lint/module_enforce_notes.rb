# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleEnforceNotes < Base

        NO_NOTES_MSG = 'Module is missing the Notes section which must include Stability, Reliability and SideEffects] - https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html'
        MISSING_KEY_MSG = 'Module is missing %s from the Notes section - https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html'
        UNKNOWN_SENTINEL_MSG = '%s uses the sentinel value %s which is not a valid metadata value. ' \
                               'Replace it with the correct values from lib/msf/core/constants.rb - ' \
                               'https://docs.metasploit.com/docs/development/developing-modules/module-metadata/definition-of-module-reliability-side-effects-and-stability.html'
        REQUIRED_KEYS = %w[Stability Reliability SideEffects]

        # Sentinel constants that exist only as placeholders -- never valid in module metadata
        SENTINEL_CONSTANTS = %i[UNKNOWN_STABILITY UNKNOWN_SIDE_EFFECTS UNKNOWN_RELIABILITY].freeze

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
          notes_present = false
          last_key = nil
          notes = nil
          hash.each_pair do |key, value|
            if key.value == 'Notes'
              notes_present = true
              notes = value
            end
            last_key = key
          end

          if notes_present
            check_for_required_keys(notes)
          else
            add_offense(last_key || hash, message: NO_NOTES_MSG)
          end
        end

        private

        def check_for_required_keys(notes)
          last_key = nil
          keys_present = []
          notes.each_pair do |key, value|
            if REQUIRED_KEYS.include? key.value
              keys_present << key.value
              check_for_sentinel_values(key, value)
            end
            last_key = key
          end

          missing_keys = REQUIRED_KEYS - keys_present
          unless missing_keys.empty?
            if missing_keys.length == 1
              msg = missing_keys[0]
            else
              msg = missing_keys[0...-1].join(', ') + ' and ' + missing_keys[-1]
            end
            add_offense(last_key || notes, message: MISSING_KEY_MSG % msg)
          end
        end

        # Flag UNKNOWN_* sentinel constants used as Notes values
        def check_for_sentinel_values(key, value)
          sentinel_nodes = collect_sentinel_nodes(value)
          sentinel_nodes.each do |sentinel_node|
            add_offense(
              sentinel_node,
              message: UNKNOWN_SENTINEL_MSG % [key.value, sentinel_node.children[1]]
            )
          end
        end

        # Collect any sentinel constant references from a value node (handles both
        # bare constants and array literals containing constants)
        def collect_sentinel_nodes(node)
          sentinels = []
          if node.const_type? && SENTINEL_CONSTANTS.include?(node.children[1])
            sentinels << node
          elsif node.array_type?
            node.children.each do |child|
              if child.const_type? && SENTINEL_CONSTANTS.include?(child.children[1])
                sentinels << child
              end
            end
          end
          sentinels
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
