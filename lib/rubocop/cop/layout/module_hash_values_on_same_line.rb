module RuboCop
  module Cop
    module Layout
      class ModuleHashValuesOnSameLine < Base
        extend AutoCorrector
        include Alignment

        MSG = "a hash value should open on the same line as its key"

        def_node_matcher :find_update_info_node, <<~PATTERN
          (def :initialize _args (begin (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...))) ...))
        PATTERN

        def_node_matcher :find_nested_update_info_node, <<~PATTERN
          (def :initialize _args (super $(send nil? {:update_info :merge_info} (lvar :info) (hash ...)) ...))
        PATTERN

        def_node_matcher :find_kwargs_hash_node, <<~PATTERN
          {
            (def :initialize _args (begin (super $(hash ...) ...) ...) ...)
            (def :initialize _args (super $(hash ...) ...) ...)
          }
        PATTERN

        def on_def(node)
          hash_node = find_hash_node(find_update_info_node(node) || find_nested_update_info_node(node)) || find_kwargs_hash_node(node)
          return if hash_node.nil?

          hash_node.pairs.each do |hash_pair|
            if requires_correction?(hash_pair)
              add_offense(hash_pair.value.location.begin, &autocorrector(hash_pair))
            end
          end
        end

        private

        def find_hash_node(update_info_node)
          return nil if update_info_node.nil?

          hash_node = update_info_node.arguments.find { |argument| hash_arg?(argument) }
          hash_node
        end

        def autocorrector(hash_pair)
          lambda do |corrector|
            key_offset = offset(hash_pair.key)
            comment_nodes = processed_source.each_comment_in_lines(hash_pair.key.first_line..hash_pair.value.first_line).to_a
            preceding_comments = comment_nodes.map { |comment| "#{comment.text}\n#{key_offset}" }.join

            correction = "#{preceding_comments}#{hash_pair.key.source} #{hash_pair.delimiter} #{hash_pair.value.source}"
            corrector.replace(hash_pair.source_range, correction)
          end
        end

        def requires_correction?(hash_pair)
          return false if hash_pair.single_line?

          hash_pair.key.first_line != hash_pair.value.first_line
        end

        def hash_arg?(node)
          node.type == :hash
        end
      end
    end
  end
end
