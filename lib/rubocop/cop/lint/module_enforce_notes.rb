# frozen_string_literal: true

module RuboCop
  module Cop
    module Lint
      class ModuleEnforceNotes < Base

        NO_NOTES_MSG = 'Module is missing the Notes section which must include Stability, Reliability and SideEffects] - https://github.com/rapid7/metasploit-framework/wiki/Definition-of-Module-Reliability,-Side-Effects,-and-Stability'
        MISSING_KEY_MSG = 'Module is missing %s from the Notes section - https://github.com/rapid7/metasploit-framework/wiki/Definition-of-Module-Reliability,-Side-Effects,-and-Stability'
        REQUIRED_KEYS = %w[Stability Reliability SideEffects]

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
          notes.each_pair do |key, _value|
            if REQUIRED_KEYS.include? key.value
              keys_present << key.value
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

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
