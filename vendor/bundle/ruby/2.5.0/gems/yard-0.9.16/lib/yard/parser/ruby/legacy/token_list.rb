# frozen_string_literal: true
module YARD
  module Parser::Ruby::Legacy
    class TokenList < Array
      include RubyToken

      def initialize(content = nil)
        self << content if content
      end

      def to_s(full_statement = false, show_block = true)
        inject([]) do |acc, token|
          break acc if !full_statement && TkStatementEnd === token
          acc << (!show_block && TkBlockContents === token ? "" : token.text)
        end.join
      end

      # @param [TokenList, Token, String] tokens
      #   A list of tokens. If the token is a string, it
      #   is parsed with {RubyLex}.
      def push(*tokens)
        tokens.each do |tok|
          if tok.is_a?(TokenList) || tok.is_a?(Array)
            concat tok
          elsif tok.is_a?(Token)
            super tok
          elsif tok.is_a?(String)
            parse_content(tok)
          else
            raise ArgumentError, "Expecting token, list of tokens or string of code to be tokenized. Got #{tok.class}"
          end
        end
        self
      end
      alias << push

      def squeeze(type = TkSPACE)
        last = nil
        TokenList.new(map {|t| x = t.is_a?(type) && last.is_a?(type) ? nil : t; last = t; x })
      end

      private

      def parse_content(content)
        lex = RubyLex.new(content)
        loop do
          tk = lex.token
          break if tk.nil?
          self << convert_token(lex, tk)
        end
      end

      def convert_token(lex, tk)
        if TkIDENTIFIER === tk && lex.peek == ':'
          next_tk = lex.token
          sym = TkLABEL.new(tk.line_no, tk.char_no, nil)
          sym.lex_state = lex.lex_state
          sym.set_text(tk.text + next_tk.text)
        elsif TkSYMBEG === tk
          next_tk = lex.token
          if next_tk
            sym = TkSYMBOL.new(tk.line_no, tk.char_no, nil)
            sym.lex_state = lex.lex_state
            sym.set_text(tk.text + next_tk.text)
          else
            tk
          end
        else
          tk
        end
      end
    end
  end
end
