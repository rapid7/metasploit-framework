# frozen_string_literal: true
module YARD
  module Parser::Ruby::Legacy
    class StatementList < Array
      include RubyToken

      attr_accessor :shebang_line, :encoding_line

      # The following list of tokens will require a block to be opened
      # if used at the beginning of a statement.
      OPEN_BLOCK_TOKENS = [TkCLASS, TkDEF, TkMODULE, TkUNTIL,
                           TkIF, TkELSIF, TkUNLESS, TkWHILE, TkFOR, TkCASE]

      # Creates a new statement list
      #
      # @param [TokenList, String] content the tokens to create the list from
      def initialize(content)
        @shebang_line = nil
        @encoding_line = nil
        @comments_last_line = nil
        if content.is_a? TokenList
          @tokens = content.dup
        elsif content.is_a? String
          @tokens = TokenList.new(content.delete("\r"))
        else
          raise ArgumentError, "Invalid content for StatementList: #{content.inspect}:#{content.class}"
        end

        parse_statements
      end

      private

      def parse_statements
        loop do
          stmt = next_statement
          break if stmt.nil?
          self << stmt
        end
      end

      # Returns the next statement in the token stream
      #
      # @return [Statement] the next statement
      def next_statement
        @state = :first_statement
        @statement_stack = []
        @level = 0
        @block_num = 0
        @done = false
        @current_block = nil
        @comments_line = nil
        @comments_hash_flag = nil
        @statement = TokenList.new
        @block = nil
        @comments = nil
        @last_tk = nil
        @last_ns_tk = nil
        @before_last_tk = nil
        @before_last_ns_tk = nil
        @first_line = nil

        until @done
          tk = @tokens.shift
          break if tk.nil?
          process_token(tk)

          @before_last_tk = @last_tk
          @last_tk = tk # Save last token
          unless [TkSPACE, TkNL, TkEND_OF_SCRIPT].include? tk.class
            @before_last_ns_tk = @last_ns_tk
            @last_ns_tk = tk
          end
        end

        # Return the code block with starting token and initial comments
        # If there is no code in the block, return nil
        @comments = @comments.compact if @comments
        if @block || !@statement.empty?
          sanitize_statement_end
          sanitize_block
          @statement.pop if [TkNL, TkSPACE, TkSEMICOLON].include?(@statement.last.class)
          stmt = Statement.new(@statement, @block, @comments)
          if @comments && @comments_line
            stmt.comments_range = (@comments_line..(@comments_line + @comments.size - 1))
            stmt.comments_hash_flag = @comments_hash_flag
          end
          stmt
        elsif @comments
          @statement << TkCOMMENT.new(@comments_line, 0)
          @statement.first.set_text("# " + @comments.join("\n# "))
          Statement.new(@statement, nil, @comments)
        end
      end

      def sanitize_statement_end
        extra = []
        (@statement.size - 1).downto(0) do |index|
          token = @statement[index]
          next unless TkStatementEnd === token

          while [TkNL, TkSPACE, TkSEMICOLON].include?(@statement[index - 1].class)
            extra.unshift(@statement.delete_at(index - 1))
            index -= 1
          end
          @statement.insert(index + 1, *extra)
          break
        end
      end

      def sanitize_block
        return unless @block
        extra = []
        while [TkSPACE, TkNL, TkSEMICOLON].include?(@block.last.class)
          next(@block.pop) if TkSEMICOLON === @block.last
          extra.unshift(@block.pop)
        end

        @statement.each_with_index do |token, index|
          if TkBlockContents === token
            @statement[index, 1] = [token, *extra]
            break
          end
        end
      end

      # Processes a single token
      #
      # @param [RubyToken::Token] tk the token to process
      def process_token(tk)
        # p tk.class, tk.text, @state, @level, @current_block, "<br/>"
        case @state
        when :first_statement
          return if process_initial_comment(tk)
          return if @statement.empty? && [TkSPACE, TkNL, TkCOMMENT].include?(tk.class)
          @comments_last_line = nil
          if @statement.empty? && tk.class == TkALIAS
            @state = :alias_statement
            @alias_values = []
            push_token(tk)
            return
          end
          return if process_simple_block_opener(tk)
          push_token(tk)
          return if process_complex_block_opener(tk)

          if balances?(tk)
            process_statement_end(tk)
          else
            @state = :balance
          end
        when :alias_statement
          push_token(tk)
          @alias_values << tk unless [TkSPACE, TkNL, TkCOMMENT].include?(tk.class)
          if @alias_values.size == 2
            @state = :first_statement
            if [NilClass, TkNL, TkEND_OF_SCRIPT, TkSEMICOLON].include?(peek_no_space.class)
              @done = true
            end
          end
        when :balance
          @statement << tk
          return unless balances?(tk)
          @state = :first_statement
          process_statement_end(tk)
        when :block_statement
          push_token(tk)
          return unless balances?(tk)
          process_statement_end(tk)
        when :pre_block
          @current_block = nil
          process_block_token(tk) unless tk.class == TkSEMICOLON
          @state = :block
        when :block
          process_block_token(tk)
        when :post_block
          if tk.class == TkSPACE
            @statement << tk
            return
          end

          process_statement_end(tk)
          @state = :block
        end

        if @first_line == tk.line_no && !@statement.empty? && TkCOMMENT === tk
          process_initial_comment(tk)
        end
      end

      # Processes a token in a block
      #
      # @param [RubyToken::Token] tk the token to process
      def process_block_token(tk)
        if balances?(tk)
          @statement << tk
          @state = :first_statement
          process_statement_end(tk)
        elsif @block_num > 1 || (@block.empty? && [TkSPACE, TkNL].include?(tk.class))
          @statement << tk
        else
          if @block.empty?
            @statement << TkBlockContents.new(tk.line_no, tk.char_no)
          end
          @block << tk
        end
      end

      # Processes a comment token that comes before a statement
      #
      # @param [RubyToken::Token] tk the token to process
      # @return [Boolean] whether or not +tk+ was processed as an initial comment
      def process_initial_comment(tk)
        if @statement.empty? && (@comments_last_line || 0) < tk.line_no - 2
          @comments = nil
        end

        return unless tk.class == TkCOMMENT

        case tk.text
        when Parser::SourceParser::SHEBANG_LINE
          if !@last_ns_tk && !@encoding_line
            @shebang_line = tk.text
            return
          end
        when Parser::SourceParser::ENCODING_LINE
          if (@last_ns_tk.class == TkCOMMENT && @last_ns_tk.text == @shebang_line) ||
             !@last_ns_tk
            @encoding_line = tk.text
            return
          end
        end

        return if !@statement.empty? && @comments
        return if @first_line && tk.line_no > @first_line

        if @comments_last_line && @comments_last_line < tk.line_no - 1
          if @comments && @statement.empty?
            @tokens.unshift(tk)
            return @done = true
          end
          @comments = nil
        end
        @comments_line = tk.line_no unless @comments

        # Remove the "#" and up to 1 space before the text
        # Since, of course, the convention is to have "# text"
        # and not "#text", which I deem ugly (you heard it here first)
        @comments ||= []
        if tk.text.start_with?('=begin')
          lines = tk.text.count("\n")
          @comments += tk.text.gsub(/\A=begin.*\r?\n|\r?\n=end.*\r?\n?\Z/, '').split(/\r?\n/)
          @comments_last_line = tk.line_no + lines
        else
          @comments << tk.text.gsub(/^(#+)\s{0,1}/, '')
          @comments_hash_flag = $1 == '##' if @comments_hash_flag.nil?
          @comments_last_line = tk.line_no
        end
        @comments.pop if @comments.size == 1 && @comments.first =~ /^\s*$/
        true
      end

      # Processes a simple block-opening token;
      # that is, a block opener such as +begin+ or +do+
      # that isn't followed by an expression
      #
      # @param [RubyToken::Token] tk the token to process
      def process_simple_block_opener(tk)
        return unless [TkLBRACE, TkDO, TkBEGIN, TkELSE].include?(tk.class) &&
                      # Make sure hashes are parsed as hashes, not as blocks
                      (@last_ns_tk.nil? || @last_ns_tk.lex_state != EXPR_BEG)

        @level += 1
        @state = :block
        @block_num += 1
        if @block.nil?
          @block = TokenList.new
          tokens = [tk, TkStatementEnd.new(tk.line_no, tk.char_no)]
          tokens = tokens.reverse if TkBEGIN === tk.class
          @statement.concat(tokens)
        else
          @statement << tk
        end

        true
      end

      # Processes a complex block-opening token;
      # that is, a block opener such as +while+ or +for+
      # that is followed by an expression
      #
      # @param [RubyToken::Token] tk the token to process
      def process_complex_block_opener(tk)
        return unless OPEN_BLOCK_TOKENS.include?(tk.class)

        @current_block = tk.class
        @state = :block_statement

        true
      end

      # Processes a token that closes a statement
      #
      # @param [RubyToken::Token] tk the token to process
      def process_statement_end(tk)
        # Whitespace means that we keep the same value of @new_statement as last token
        return if tk.class == TkSPACE

        return unless
          # We might be coming after a statement-ending token...
          (@last_tk && [TkSEMICOLON, TkNL, TkEND_OF_SCRIPT].include?(tk.class)) ||
          # Or we might be at the beginning of an argument list
          (@current_block == TkDEF && tk.class == TkRPAREN)

        # Continue line ending on . or ::
        return if @last_tk && [EXPR_DOT].include?(@last_tk.lex_state)

        # Continue a possible existing new statement unless we just finished an expression...
        return unless (@last_tk && [EXPR_END, EXPR_ARG].include?(@last_tk.lex_state)) ||
                      # Or we've opened a block and are ready to move into the body
                      (@current_block && [TkNL, TkSEMICOLON].include?(tk.class) &&
                       # Handle the case where the block statement's expression is on the next line
                       #
                       # while
                       #     foo
                       # end
                       @last_ns_tk.class != @current_block &&
                       # And the case where part of the expression is on the next line
                       #
                       # while foo ||
                       #     bar
                       # end
                       @last_tk.lex_state != EXPR_BEG)

        # Continue with the statement if we've hit a comma in a def
        return if @current_block == TkDEF && peek_no_space.class == TkCOMMA

        if [TkEND_OF_SCRIPT, TkNL, TkSEMICOLON].include?(tk.class) && @state == :block_statement &&
           [TkRBRACE, TkEND].include?(@last_ns_tk.class) && @level == 0
          @current_block = nil
        end

        unless @current_block
          @done = true
          return
        end

        @state = :pre_block
        @level += 1
        @block_num += 1
        unless @block
          @block = TokenList.new
          @statement << TkStatementEnd.new(tk.line_no, tk.char_no)
        end
      end

      # Handles the balancing of parentheses and blocks
      #
      # @param [RubyToken::Token] tk the token to process
      # @return [Boolean] whether or not the current statement's parentheses and blocks
      #   are balanced after +tk+
      def balances?(tk)
        unless [TkALIAS, TkDEF].include?(@last_ns_tk.class) || @before_last_ns_tk.class == TkALIAS
          if [TkLPAREN, TkLBRACK, TkLBRACE, TkDO, TkBEGIN].include?(tk.class)
            @level += 1
          elsif OPEN_BLOCK_TOKENS.include?(tk.class)
            @level += 1 unless tk.class == TkELSIF
          elsif [TkRPAREN, TkRBRACK, TkRBRACE, TkEND].include?(tk.class) && @level > 0
            @level -= 1
          end
        end

        @level == 0
      end

      # Adds a token to the current statement,
      # unless it's a newline, semicolon, or comment
      #
      # @param [RubyToken::Token] tk the token to process
      def push_token(tk)
        @first_line = tk.line_no if @statement.empty?
        @statement << tk unless @level == 0 && [TkCOMMENT].include?(tk.class)
      end

      # Returns the next token in the stream that's not a space
      #
      # @return [RubyToken::Token] the next non-space token
      def peek_no_space
        return @tokens.first unless @tokens.first.class == TkSPACE
        @tokens[1]
      end
    end
  end
end
