# frozen_string_literal: true
module YARD
  module Parser::Ruby::Legacy
    class Statement
      attr_reader :tokens, :comments, :block
      attr_accessor :comments_range

      # @deprecated Groups are now defined by directives
      # @see Tags::GroupDirective
      attr_accessor :group

      attr_accessor :comments_hash_flag

      def initialize(tokens, block = nil, comments = nil)
        @tokens = tokens
        @block  = block
        @comments = comments
        @comments_hash_flag = false
      end

      def first_line
        to_s.split(/\n/)[0]
      end

      def to_s(include_block = true)
        tokens.map do |token|
          RubyToken::TkBlockContents === token ? (include_block ? block.to_s : '') : token.text
        end.join
      end
      alias source to_s

      def inspect
        l = line - 1
        to_s(false).split(/\n/).map do |text|
          "\t#{l += 1}:  #{text}"
        end.join("\n")
      end

      def show
        "\t#{line}: #{first_line}"
      end

      # @return [Fixnum] the first line of Ruby source
      def line
        tokens.first.line_no
      end

      # @return [Range<Fixnum>] the first to last lines of Ruby source
      # @since 0.5.4
      def line_range
        tokens.first.line_no..tokens.last.line_no
      end

      private

      def clean_tokens(tokens)
        last_tk = nil
        tokens.reject do |tk|
          tk.is_a?(RubyToken::TkNL) ||
            (last_tk.is_a?(RubyToken::TkSPACE) &&
            last_tk.class == tk.class) && last_tk = tk
        end
      end
    end
  end
end
