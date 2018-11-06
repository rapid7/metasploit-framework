module RSpec
  module Expectations
    # @private
    class BlockSnippetExtractor # rubocop:disable Metrics/ClassLength
      # rubocop should properly handle `Struct.new {}` as an inner class definition.

      attr_reader :proc, :method_name

      def self.try_extracting_single_line_body_of(proc, method_name)
        lines = new(proc, method_name).body_content_lines
        return nil unless lines.count == 1
        lines.first
      rescue Error
        nil
      end

      def initialize(proc, method_name)
        @proc = proc
        @method_name = method_name.to_s.freeze
      end

      # Ideally we should properly handle indentations of multiline snippet,
      # but it's not implemented yet since because we use result of this method only when it's a
      # single line and implementing the logic introduces additional complexity.
      def body_content_lines
        raw_body_lines.map(&:strip).reject(&:empty?)
      end

    private

      def raw_body_lines
        raw_body_snippet.split("\n")
      end

      def raw_body_snippet
        block_token_extractor.body_tokens.map(&:string).join
      end

      def block_token_extractor
        @block_token_extractor ||= BlockTokenExtractor.new(method_name, source, beginning_line_number)
      end

      if RSpec.respond_to?(:world)
        def source
          raise TargetNotFoundError unless File.exist?(file_path)
          RSpec.world.source_from_file(file_path)
        end
      else
        RSpec::Support.require_rspec_support 'source'
        def source
          raise TargetNotFoundError unless File.exist?(file_path)
          @source ||= RSpec::Support::Source.from_file(file_path)
        end
      end

      def file_path
        source_location.first
      end

      def beginning_line_number
        source_location.last
      end

      def source_location
        proc.source_location || raise(TargetNotFoundError)
      end

      Error = Class.new(StandardError)
      TargetNotFoundError = Class.new(Error)
      AmbiguousTargetError = Class.new(Error)

      # @private
      # Performs extraction of block body snippet using tokens,
      # which cannot be done with node information.
      BlockTokenExtractor = Struct.new(:method_name, :source, :beginning_line_number) do
        attr_reader :state, :body_tokens

        def initialize(*)
          super
          parse!
        end

        private

        def parse!
          @state = :initial

          catch(:finish) do
            source.tokens.each do |token|
              invoke_state_handler(token)
            end
          end
        end

        def finish!
          throw :finish
        end

        def invoke_state_handler(token)
          __send__("#{state}_state", token)
        end

        def initial_state(token)
          @state = :after_method_call if token.location == block_locator.method_call_location
        end

        def after_method_call_state(token)
          @state = :after_opener if handle_opener_token(token)
        end

        def after_opener_state(token)
          if handle_closer_token(token)
            finish_or_find_next_block_if_incorrect!
          elsif pipe_token?(token)
            finalize_pending_tokens!
            @state = :after_beginning_of_args
          else
            pending_tokens << token
            handle_opener_token(token)
            @state = :after_beginning_of_body unless token.type == :on_sp
          end
        end

        def after_beginning_of_args_state(token)
          @state = :after_beginning_of_body if pipe_token?(token)
        end

        def after_beginning_of_body_state(token)
          if handle_closer_token(token)
            finish_or_find_next_block_if_incorrect!
          else
            pending_tokens << token
            handle_opener_token(token)
          end
        end

        def pending_tokens
          @pending_tokens ||= []
        end

        def finalize_pending_tokens!
          pending_tokens.freeze.tap do
            @pending_tokens = nil
          end
        end

        def finish_or_find_next_block_if_incorrect!
          body_tokens = finalize_pending_tokens!

          if correct_block?(body_tokens)
            @body_tokens = body_tokens
            finish!
          else
            @state = :after_method_call
          end
        end

        def handle_opener_token(token)
          opener_token?(token).tap do |boolean|
            opener_token_stack.push(token) if boolean
          end
        end

        def opener_token?(token)
          token.type == :on_lbrace || (token.type == :on_kw && token.string == 'do')
        end

        def handle_closer_token(token)
          if opener_token_stack.last.closed_by?(token)
            opener_token_stack.pop
            opener_token_stack.empty?
          else
            false
          end
        end

        def opener_token_stack
          @opener_token_stack ||= []
        end

        def pipe_token?(token)
          token.type == :on_op && token.string == '|'
        end

        def correct_block?(body_tokens)
          return true if block_locator.body_content_locations.empty?
          content_location = block_locator.body_content_locations.first
          content_location.between?(body_tokens.first.location, body_tokens.last.location)
        end

        def block_locator
          @block_locator ||= BlockLocator.new(method_name, source, beginning_line_number)
        end
      end

      # @private
      # Locates target block with node information (semantics), which tokens don't have.
      BlockLocator = Struct.new(:method_name, :source, :beginning_line_number) do
        def method_call_location
          @method_call_location ||= method_ident_node.location
        end

        def body_content_locations
          @body_content_locations ||= block_body_node.map(&:location).compact
        end

        private

        def method_ident_node
          method_call_node = block_wrapper_node.children.first
          method_call_node.find do |node|
            method_ident_node?(node)
          end
        end

        def block_body_node
          block_node = block_wrapper_node.children[1]
          block_node.children.last
        end

        def block_wrapper_node
          case candidate_block_wrapper_nodes.size
          when 1
            candidate_block_wrapper_nodes.first
          when 0
            raise TargetNotFoundError
          else
            raise AmbiguousTargetError
          end
        end

        def candidate_block_wrapper_nodes
          @candidate_block_wrapper_nodes ||= candidate_method_ident_nodes.map do |method_ident_node|
            block_wrapper_node = method_ident_node.each_ancestor.find { |node| node.type == :method_add_block }
            next nil unless block_wrapper_node
            method_call_node = block_wrapper_node.children.first
            method_call_node.include?(method_ident_node) ? block_wrapper_node : nil
          end.compact
        end

        def candidate_method_ident_nodes
          source.nodes_by_line_number[beginning_line_number].select do |node|
            method_ident_node?(node)
          end
        end

        def method_ident_node?(node)
          node.type == :@ident && node.args.first == method_name
        end
      end
    end
  end
end
