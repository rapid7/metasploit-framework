# frozen_string_literal: trueAdd commentMore actions

module RuboCop
  module Cop
    module Lint
      # Checks for leading or trailing whitespace in Metasploit module metadata keys/values
      # inside the initialize method. Recursively checks all hash and array values, except for
      # keys listed in EXEMPT_KEYS.
      #
      # EXEMPT_KEYS can be extended to skip additional metadata fields as needed.
      #
      # @example
      #   # bad
      #   'Name' => ' value '
      #   'Author' => [' hd']
      #
      #   # good
      #   'Name' => 'value'
      #   'Author' => ['hd']
      class DetectMetadataTrailingLeadingWhitespace < Base
        extend AutoCorrector
        MSG = 'Metadata key or value has leading or trailing whitespace.'
        EXEMPT_KEYS = %w[Description Payload BadChars].freeze

        # Called for every method definition node
        # Only processes the initialize method
        # @param node [RuboCop::AST::DefNode]
        def on_def(node)
          return unless node.method_name == :initialize

          node.each_descendant(:hash) do |hash_node|
            hash_node.pairs.each do |pair|
              key = extract_string(pair.key)
              next if key && EXEMPT_KEYS.any? { |exempt| key.casecmp?(exempt) }
              check_value(pair.value)
              if key && (key != key.strip)
                add_offense(pair.key, message: MSG) do |corrector|
                  corrector.replace(pair.key.loc.expression, key.strip.inspect)
                end
              end
            end
          end
        end

        private

        # Recursively checks a value node for whitespace issues
        # @param node [RuboCop::AST::Node]
        def check_value(node)
          case node.type
          when :str, :dstr
            value = extract_string(node)
            if value && value != value.strip
              add_offense(node, message: MSG) do |corrector|
                replacement = node.sym_type? ? ":#{value.strip}" : value.strip.inspect
                corrector.replace(node.loc.expression, replacement)
              end
            end
          when :array
            node.children.each { |child| check_value(child) }
          when :hash
            node.pairs.each do |pair|
              key = extract_string(pair.key)
              next if key && EXEMPT_KEYS.any? { |exempt| key.casecmp?(exempt) }
              if key && key != key.strip
                add_offense(pair.key, message: MSG) do |corrector|
                  corrector.replace(pair.key.loc.expression, key.strip.inspect)
                end
              end
              check_value(pair.value)
            end
          end
        end

        # Extracts the string value from a node (handles str, sym, dstr)
        # @param node [RuboCop::AST::Node]
        # @return [String, nil]
        def extract_string(node)
          return unless node
          if node.str_type? || node.sym_type?
            node.value.to_s
          elsif node.dstr_type?
            # For dynamic strings, join all child string values
            node.children.map { |c| c.is_a?(Parser::AST::Node) ? extract_string(c) : c.to_s }.join
          end
        end
      end
    end
  end
end
