require "e2mmap"
require "irb/slex"

module YARD
  module Parser::Ruby::Legacy
    # Legacy lexical tokenizer module.
    module RubyToken
      EXPR_BEG   = :EXPR_BEG
      EXPR_MID   = :EXPR_MID
      EXPR_END   = :EXPR_END
      EXPR_ARG   = :EXPR_ARG
      EXPR_FNAME = :EXPR_FNAME
      EXPR_DOT   = :EXPR_DOT
      EXPR_CLASS = :EXPR_CLASS

      # Represents a token in the Ruby lexer
      class Token
        # @return [Integer] the line number in the file/stream the token is
        #   located.
        attr_reader :line_no

        # @return [Integer] the character number in the file/stream the token
        #   is located.
        attr_reader :char_no

        # @return [String] the token text value
        attr_reader :text

        # @return [Symbol] the lexical state at the token
        attr_accessor :lex_state

        # @private
        NO_TEXT = "??".freeze

        # Creates a new Token object
        # @param [Integer] line_no the line number to initialize the token to
        # @param [Integer] char_no the char number to initialize the token to
        def initialize(line_no, char_no)
          @line_no = line_no
          @char_no = char_no
          @text    = NO_TEXT
        end

        # Chainable way to sets the text attribute
        #
        # @param [String] text the new text
        # @return [Token] this token object
        def set_text(text)
          @text = text
          self
        end
      end

      # Represents a block
      class TkBlockContents < Token
        def text; '...' end
      end

      # Represents an end statement
      class TkStatementEnd < Token
        def text; '' end
      end

      class TkNode < Token
        attr :node
      end

      # Represents whitespace
      class TkWhitespace < Token
      end

      # Represents a Ruby identifier
      class TkId < Token
        def initialize(line_no, char_no, name)
          super(line_no, char_no)
          @name = name
        end
        attr :name
      end

      # Represents a Ruby keyword
      class TkKW < TkId
      end

      # Represents a Ruby value
      class TkVal < Token
        def initialize(line_no, char_no, value = nil)
          super(line_no, char_no)
          set_text(value)
        end
      end

      class TkOp < Token
        def name
          self.class.op_name
        end
      end

      class TkOPASGN < TkOp
        def initialize(line_no, char_no, op)
          super(line_no, char_no)
          op = TkReading2Token[op] unless op.is_a?(Symbol)
          @op = op
        end
        attr :op
      end

      class TkUnknownChar < Token
        def initialize(line_no, char_no, _id)
          super(line_no, char_no)
          @name = char_no > 255 ? '?' : char_no.chr
        end
        attr :name
      end

      class TkError < Token
      end

      # @private
      def set_token_position(line, char)
        @prev_line_no = line
        @prev_char_no = char
      end

      # @private
      def Token(token, value = nil) # rubocop:disable Style/MethodName
        tk = nil
        case token
        when String, Symbol
          source = token.is_a?(String) ? TkReading2Token : TkSymbol2Token
          if (tk = source[token]).nil?
            IRB.fail TkReading2TokenNoKey, token
          end
          tk = Token(tk[0], value)
        else
          if token
            tk = if (token.ancestors & [TkId, TkVal, TkOPASGN, TkUnknownChar]).empty?
                   token.new(@prev_line_no, @prev_char_no)
                 else
                   token.new(@prev_line_no, @prev_char_no, value)
                 end
          end
        end
        tk
      end

      # @private
      TokenDefinitions = [
        [:TkCLASS,      TkKW,  "class",  EXPR_CLASS],
        [:TkMODULE,     TkKW,  "module", EXPR_BEG],
        [:TkDEF,        TkKW,  "def",    EXPR_FNAME],
        [:TkUNDEF,      TkKW,  "undef",  EXPR_FNAME],
        [:TkBEGIN,      TkKW,  "begin",  EXPR_BEG],
        [:TkRESCUE,     TkKW,  "rescue", EXPR_MID],
        [:TkENSURE,     TkKW,  "ensure", EXPR_BEG],
        [:TkEND,        TkKW,  "end",    EXPR_END],
        [:TkIF,         TkKW,  "if",     EXPR_BEG, :TkIF_MOD],
        [:TkUNLESS,     TkKW,  "unless", EXPR_BEG, :TkUNLESS_MOD],
        [:TkTHEN,       TkKW,  "then",   EXPR_BEG],
        [:TkELSIF,      TkKW,  "elsif",  EXPR_BEG],
        [:TkELSE,       TkKW,  "else",   EXPR_BEG],
        [:TkCASE,       TkKW,  "case",   EXPR_BEG],
        [:TkWHEN,       TkKW,  "when",   EXPR_BEG],
        [:TkWHILE,      TkKW,  "while",  EXPR_BEG, :TkWHILE_MOD],
        [:TkUNTIL,      TkKW,  "until",  EXPR_BEG, :TkUNTIL_MOD],
        [:TkFOR,        TkKW,  "for",    EXPR_BEG],
        [:TkBREAK,      TkKW,  "break",  EXPR_END],
        [:TkNEXT,       TkKW,  "next",   EXPR_END],
        [:TkREDO,       TkKW,  "redo",   EXPR_END],
        [:TkRETRY,      TkKW,  "retry",  EXPR_END],
        [:TkIN,         TkKW,  "in",     EXPR_BEG],
        [:TkDO,         TkKW,  "do",     EXPR_BEG],
        [:TkRETURN,     TkKW,  "return", EXPR_MID],
        [:TkYIELD,      TkKW,  "yield",  EXPR_END],
        [:TkSUPER,      TkKW,  "super",  EXPR_END],
        [:TkSELF,       TkKW,  "self",   EXPR_END],
        [:TkNIL,        TkKW,  "nil",    EXPR_END],
        [:TkTRUE,       TkKW,  "true",   EXPR_END],
        [:TkFALSE,      TkKW,  "false",  EXPR_END],
        [:TkAND,        TkKW,  "and",    EXPR_BEG],
        [:TkOR,         TkKW,  "or",     EXPR_BEG],
        [:TkNOT,        TkKW,  "not",    EXPR_BEG],
        [:TkIF_MOD,     TkKW],
        [:TkUNLESS_MOD, TkKW],
        [:TkWHILE_MOD,  TkKW],
        [:TkUNTIL_MOD,  TkKW],
        [:TkALIAS,      TkKW,  "alias",    EXPR_FNAME],
        [:TkDEFINED,    TkKW,  "defined?", EXPR_END],
        [:TklBEGIN,     TkKW,  "BEGIN",    EXPR_END],
        [:TklEND,       TkKW,  "END",      EXPR_END],
        [:Tk__LINE__,   TkKW,  "__LINE__", EXPR_END],
        [:Tk__FILE__,   TkKW,  "__FILE__", EXPR_END],
        [:TkIDENTIFIER, TkId],
        [:TkFID,        TkId],
        [:TkGVAR,       TkId],
        [:TkIVAR,       TkId],
        [:TkCONSTANT,   TkId],
        [:TkINTEGER,    TkVal],
        [:TkFLOAT,      TkVal],
        [:TkSYMBOL,     TkVal],
        [:TkLABEL,      TkVal],
        [:TkSTRING,     TkVal],
        [:TkXSTRING,    TkVal],
        [:TkREGEXP,     TkVal],
        [:TkCOMMENT,    TkVal],
        [:TkDSTRING,    TkNode],
        [:TkDXSTRING,   TkNode],
        [:TkDREGEXP,    TkNode],
        [:TkNTH_REF,    TkId],
        [:TkBACK_REF,   TkId],
        [:TkUPLUS,      TkOp,   "+@"],
        [:TkUMINUS,     TkOp,   "-@"],
        [:TkPOW,        TkOp,   "**"],
        [:TkCMP,        TkOp,   "<=>"],
        [:TkEQ,         TkOp,   "=="],
        [:TkEQQ,        TkOp,   "==="],
        [:TkNEQ,        TkOp,   "!="],
        [:TkGEQ,        TkOp,   ">="],
        [:TkLEQ,        TkOp,   "<="],
        [:TkANDOP,      TkOp,   "&&"],
        [:TkOROP,       TkOp,   "||"],
        [:TkMATCH,      TkOp,   "=~"],
        [:TkNMATCH,     TkOp,   "!~"],
        [:TkDOT2,       TkOp,   ".."],
        [:TkDOT3,       TkOp,   "..."],
        [:TkAREF,       TkOp,   "[]"],
        [:TkASET,       TkOp,   "[]="],
        [:TkLSHFT,      TkOp,   "<<"],
        [:TkRSHFT,      TkOp,   ">>"],
        [:TkCOLON2,     TkOp],
        [:TkCOLON3,     TkOp],
        [:OPASGN,       TkOp], # +=, -=  etc. #
        [:TkASSOC,      TkOp,   "=>"],
        [:TkQUESTION,   TkOp,   "?"], #?
        [:TkCOLON,      TkOp,   ":"], #:
        [:TkSTAR],            # *arg
        [:TkAMPER],           # &arg #
        [:TkSYMBEG,     TkId],
        [:TkGT,         TkOp,   ">"],
        [:TkLT,         TkOp,   "<"],
        [:TkPLUS,       TkOp,   "+"],
        [:TkMINUS,      TkOp,   "-"],
        [:TkMULT,       TkOp,   "*"],
        [:TkDIV,        TkOp,   "/"],
        [:TkMOD,        TkOp,   "%"],
        [:TkBITOR,      TkOp,   "|"],
        [:TkBITXOR,     TkOp,   "^"],
        [:TkBITAND,     TkOp,   "&"],
        [:TkBITNOT,     TkOp,   "~"],
        [:TkNOTOP,      TkOp,   "!"],
        [:TkBACKQUOTE,  TkOp,   "`"],
        [:TkASSIGN,     Token,  "="],
        [:TkDOT,        Token,  "."],
        [:TkLPAREN,     Token,  "("],  # (exp)
        [:TkLBRACK,     Token,  "["],  # [arry]
        [:TkLBRACE,     Token,  "{"],  # {hash}
        [:TkRPAREN,     Token,  ")"],
        [:TkRBRACK,     Token,  "]"],
        [:TkRBRACE,     Token,  "}"],
        [:TkCOMMA,      Token,  ","],
        [:TkSEMICOLON,  Token,  ";"],
        [:TkSPACE,          TkWhitespace],
        [:TkNL,             TkWhitespace],
        [:TkEND_OF_SCRIPT,  TkWhitespace],
        [:TkBACKSLASH,  TkUnknownChar,  "\\"],
        [:TkAT,         TkUnknownChar,  "@"],
        [:TkDOLLAR,     TkUnknownChar,  "\$"]
      ]

      # { reading => token_class }
      # { reading => [token_class, *opt] }
      TkReading2Token = {}
      TkSymbol2Token = {}

      # @private
      def self.def_token(token_n, super_token = Token, reading = nil, *opts)
        token_n = token_n.id2name unless token_n.is_a?(String)
        if RubyToken.const_defined?(token_n)
          # IRB.fail AlreadyDefinedToken, token_n
        end

        token_c = Class.new super_token
        RubyToken.const_set token_n, token_c
        # token_c.inspect

        if reading
          if TkReading2Token[reading]
            IRB.fail TkReading2TokenDuplicateError, token_n, reading
          end
          if opts.empty?
            TkReading2Token[reading] = [token_c]
          else
            TkReading2Token[reading] = [token_c].concat(opts)
          end
        end
        TkSymbol2Token[token_n.intern] = token_c

        if token_c <= TkOp
          token_c.class_eval %{
            def self.op_name; "#{reading}"; end
          }
        end
      end

      for defs in TokenDefinitions
        def_token(*defs)
      end

      NEWLINE_TOKEN = TkNL.new(0, 0)
      NEWLINE_TOKEN.set_text("\n")
    end

    # Lexical analyzer for Ruby source
    # @private
    class RubyLex
      # Read an input stream character by character. We allow for unlimited
      # ungetting of characters just read.
      #
      # We simplify the implementation greatly by reading the entire input
      # into a buffer initially, and then simply traversing it using
      # pointers.
      #
      # We also have to allow for the <i>here document diversion</i>. This
      # little gem comes about when the lexer encounters a here
      # document. At this point we effectively need to split the input
      # stream into two parts: one to read the body of the here document,
      # the other to read the rest of the input line where the here
      # document was initially encountered. For example, we might have
      #
      #   do_something(<<-A, <<-B)
      #     stuff
      #     for
      #   A
      #     stuff
      #     for
      #   B
      #
      # When the lexer encounters the <<A, it reads until the end of the
      # line, and keeps it around for later. It then reads the body of the
      # here document.  Once complete, it needs to read the rest of the
      # original line, but then skip the here document body.
      #
      # @private
      class BufferedReader
        attr_reader :line_num

        def initialize(content)
          if /\t/ =~ content
            tab_width = 2
            content = content.split(/\n/).map do |line|
              1 while line.gsub!(/\t+/) { ' ' * (tab_width * $&.length - $`.length % tab_width) } && $~ #`
              line
            end .join("\n")
          end
          @content = String.new(content)
          @content << "\n" unless @content[-1, 1] == "\n"
          @size      = @content.size
          @offset    = 0
          @hwm       = 0
          @line_num  = 1
          @read_back_offset = 0
          @last_newline = 0
          @newline_pending = false
        end

        def column
          @offset - @last_newline
        end

        def getc
          return nil if @offset >= @size
          ch = @content[@offset, 1]

          @offset += 1
          @hwm = @offset if @hwm < @offset

          if @newline_pending
            @line_num += 1
            @last_newline = @offset - 1
            @newline_pending = false
          end

          if ch == "\n"
            @newline_pending = true
          end
          ch
        end

        def getc_already_read
          getc
        end

        def ungetc(_ch)
          raise "unget past beginning of file" if @offset <= 0
          @offset -= 1
          if @content[@offset] == ?\n
            @newline_pending = false
          end
        end

        def get_read
          res = @content[@read_back_offset...@offset]
          @read_back_offset = @offset
          res
        end

        def peek(at)
          pos = @offset + at
          if pos >= @size
            nil
          else
            @content[pos, 1]
          end
        end

        def peek_equal(str)
          @content[@offset, str.length] == str
        end

        def divert_read_from(reserve)
          @content[@offset, 0] = reserve
          @size = @content.size
        end
      end

      # end of nested class BufferedReader

      extend Exception2MessageMapper
      def_exception(:AlreadyDefinedToken, "Already defined token(%s)")
      def_exception(:TkReading2TokenNoKey, "key nothing(key='%s')")
      def_exception(:TkSymbol2TokenNoKey, "key nothing(key='%s')")
      def_exception(:TkReading2TokenDuplicateError,
        "key duplicate(token_n='%s', key='%s')")
      def_exception(:SyntaxError, "%s")

      include RubyToken
      include IRB

      attr_reader :continue
      attr_reader :lex_state

      def self.debug?
        false
      end

      def initialize(content)
        lex_init

        @reader = BufferedReader.new(content)

        @exp_line_no = @line_no = 1
        @base_char_no = 0
        @indent = 0

        @ltype = nil
        @quoted = nil
        @lex_state = EXPR_BEG
        @space_seen = false

        @continue = false
        @line = ""

        @skip_space = false
        @read_auto_clean_up = false
        @exception_on_syntax_error = true

        @colonblock_seen = false
      end

      attr_accessor :skip_space
      attr_accessor :read_auto_clean_up
      attr_accessor :exception_on_syntax_error

      attr :indent

      # io functions
      def line_no
        @reader.line_num
      end

      def char_no
        @reader.column
      end

      def get_read
        @reader.get_read
      end

      def getc
        @reader.getc
      end

      def getc_of_rests
        @reader.getc_already_read
      end

      def gets
        (c = getc) || return
        l = ""
        begin
          l.concat c unless c == "\r"
          break if c == "\n"
        end while c = getc # rubocop:disable Lint/Loop
        l
      end

      def ungetc(c = nil)
        @reader.ungetc(c)
      end

      def peek_equal?(str)
        @reader.peek_equal(str)
      end

      def peek(i = 0)
        @reader.peek(i)
      end

      def lex
        catch(:eof) do
          until ((tk = token).is_a?(TkNL) || tk.is_a?(TkEND_OF_SCRIPT)) &&
                !@continue ||
                tk.nil?
          end
          line = get_read

          if line == "" && tk.is_a?(TkEND_OF_SCRIPT) || tk.nil?
            nil
          else
            line
          end
        end
      end

      def token
        set_token_position(line_no, char_no)
        catch(:eof) do
          begin
            begin
              tk = @OP.match(self)
              @space_seen = tk.is_a?(TkSPACE)
            rescue SyntaxError
              abort if @exception_on_syntax_error
              tk = TkError.new(line_no, char_no)
            end
          end while @skip_space && tk.is_a?(TkSPACE)
          if @read_auto_clean_up
            get_read
          end
          # throw :eof unless tk
          p tk if $DEBUG
          tk.lex_state = lex_state if tk
          tk
        end
      end

      ENINDENT_CLAUSE = [
        "case", "class", "def", "do", "for", "if",
        "module", "unless", "until", "while", "begin"
      ] #, "when"
      ACCEPTS_COLON = ["if", "for", "unless", "until", "while"]
      DEINDENT_CLAUSE = ["end"] #, "when"

      PERCENT_LTYPE = {
        "q" => "\'",
        "Q" => "\"",
        "x" => "\`",
        "r" => "/",
        "w" => "]",
        "W" => "]"
      }

      PERCENT_PAREN = {
        "{" => "}",
        "[" => "]",
        "<" => ">",
        "(" => ")"
      }

      Ltype2Token = {
        "\'" => TkSTRING,
        "\"" => TkSTRING,
        "\`" => TkXSTRING,
        "/" => TkREGEXP,
        "]" => TkDSTRING
      }
      Ltype2Token.default = TkSTRING

      DLtype2Token = {
        "\"" => TkDSTRING,
        "\`" => TkDXSTRING,
        "/" => TkDREGEXP
      }

      def lex_init()
        @OP = SLex.new
        @OP.def_rules("\0", "\004", "\032") do |chars, _io|
          Token(TkEND_OF_SCRIPT).set_text(chars)
        end

        @OP.def_rules(" ", "\t", "\f", "\r", "\13") do |chars, _io|
          @space_seen = true
          while (ch = getc) =~ /[ \t\f\r\13]/
            chars << ch
          end
          ungetc
          Token(TkSPACE).set_text(chars)
        end

        @OP.def_rule("#") do |_op, _io|
          identify_comment
        end

        @OP.def_rule("=begin", proc { @prev_char_no == 0 && peek(0) =~ /\s/ }) do |op, _io|
          str = String.new(op)
          @ltype = "="

          begin
            line = String.new
            begin
              ch = getc
              line << ch
            end until ch == "\n"
            str << line
          end until line =~ /^=end/

          ungetc

          @ltype = nil

          if str =~ /\A=begin\s+rdoc/i
            str.sub!(/\A=begin.*\n/, '')
            str.sub!(/^=end.*/m, '')
            Token(TkCOMMENT).set_text(str)
          else
            Token(TkCOMMENT).set_text(str)
          end
        end

        @OP.def_rule("\n") do
          print "\\n\n" if RubyLex.debug?
          @colonblock_seen = false
          case @lex_state
          when EXPR_BEG, EXPR_FNAME, EXPR_DOT
            @continue = true
          else
            @continue = false
            @lex_state = EXPR_BEG
          end
          Token(TkNL).set_text("\n")
        end

        @OP.def_rules("*", "**",
          "!", "!=", "!~",
          "=", "==", "===",
          "=~", "<=>",
          "<", "<=",
          ">", ">=", ">>") do |op, _io|
          @lex_state = EXPR_BEG
          Token(op).set_text(op)
        end

        @OP.def_rules("<<") do |op, _io|
          tk = nil
          if @lex_state != EXPR_END && @lex_state != EXPR_CLASS &&
             (@lex_state != EXPR_ARG || @space_seen)
            c = peek(0)
            tk = identify_here_document if /[-\w\"\'\`]/ =~ c
          end
          if !tk
            @lex_state = EXPR_BEG
            tk = Token(op).set_text(op)
          end
          tk
        end

        @OP.def_rules("'", '"') do |op, _io|
          identify_string(op)
        end

        @OP.def_rules("`") do |op, _io|
          if @lex_state == EXPR_FNAME
            Token(op).set_text(op)
          else
            identify_string(op)
          end
        end

        @OP.def_rules('?') do |op, _io|
          if @lex_state == EXPR_END
            @lex_state = EXPR_BEG
            Token(TkQUESTION).set_text(op)
          else
            ch = getc
            if @lex_state == EXPR_ARG && ch !~ /\s/
              ungetc
              @lex_state = EXPR_BEG
              Token(TkQUESTION).set_text(op)
            else
              str = String.new(op)
              str << ch
              if ch == '\\' #'
                str << read_escape
              end
              @lex_state = EXPR_END
              Token(TkINTEGER).set_text(str)
            end
          end
        end

        @OP.def_rules("&", "&&", "|", "||") do |op, _io|
          @lex_state = EXPR_BEG
          Token(op).set_text(op)
        end

        @OP.def_rules("+=", "-=", "*=", "**=",
          "&=", "|=", "^=", "<<=", ">>=", "||=", "&&=") do |op, _io|
          @lex_state = EXPR_BEG
          op =~ /^(.*)=$/
          Token(TkOPASGN, $1).set_text(op)
        end

        @OP.def_rule("+@", proc { @lex_state == EXPR_FNAME }) do |op, _io|
          Token(TkUPLUS).set_text(op)
        end

        @OP.def_rule("-@", proc { @lex_state == EXPR_FNAME }) do |op, _io|
          Token(TkUMINUS).set_text(op)
        end

        @OP.def_rules("+", "-") do |op, _io|
          catch(:RET) do
            if @lex_state == EXPR_ARG
              if @space_seen && peek(0) =~ /[0-9]/
                throw :RET, identify_number(op)
              else
                @lex_state = EXPR_BEG
              end
            elsif @lex_state != EXPR_END && peek(0) =~ /[0-9]/
              throw :RET, identify_number(op)
            else
              @lex_state = EXPR_BEG
            end
            Token(op).set_text(op)
          end
        end

        @OP.def_rule(".") do
          @lex_state = EXPR_BEG
          if peek(0) =~ /[0-9]/
            ungetc
            identify_number("")
          else
            # for obj.if
            @lex_state = EXPR_DOT
            Token(TkDOT).set_text(".")
          end
        end

        @OP.def_rules("..", "...") do |op, _io|
          @lex_state = EXPR_BEG
          Token(op).set_text(op)
        end

        lex_int2
      end

      def lex_int2
        @OP.def_rules("]", "}", ")") do |op, _io|
          @lex_state = EXPR_END
          @indent -= 1
          Token(op).set_text(op)
        end

        @OP.def_rule(":") do
          if (@colonblock_seen && @lex_state != EXPR_BEG) || peek(0) =~ /\s/
            @lex_state = EXPR_BEG
            tk = Token(TkCOLON)
          else
            @lex_state = EXPR_FNAME
            tk = Token(TkSYMBEG)
          end
          tk.set_text(":")
        end

        @OP.def_rule("::") do
          # p @lex_state.id2name, @space_seen
          if @lex_state == EXPR_BEG || @lex_state == EXPR_ARG && @space_seen
            @lex_state = EXPR_BEG
            tk = Token(TkCOLON3)
          else
            @lex_state = EXPR_DOT
            tk = Token(TkCOLON2)
          end
          tk.set_text("::")
        end

        @OP.def_rule("/") do |op, _io|
          if @lex_state == EXPR_BEG || @lex_state == EXPR_MID
            identify_string(op)
          elsif peek(0) == '='
            getc
            @lex_state = EXPR_BEG
            Token(TkOPASGN, :/).set_text("/=") #")
          elsif @lex_state == EXPR_ARG && @space_seen && peek(0) !~ /\s/
            identify_string(op)
          else
            @lex_state = EXPR_BEG
            Token("/").set_text(op)
          end
        end

        @OP.def_rules("^") do
          @lex_state = EXPR_BEG
          Token("^").set_text("^")
        end

        # @OP.def_rules("^=") do
        #   @lex_state = EXPR_BEG
        #   Token(TkOPASGN, :^)
        # end

        @OP.def_rules(",", ";") do |op, _io|
          @colonblock_seen = false
          @lex_state = EXPR_BEG
          Token(op).set_text(op)
        end

        @OP.def_rule("~") do
          @lex_state = EXPR_BEG
          Token("~").set_text("~")
        end

        @OP.def_rule("~@", proc { @lex_state = EXPR_FNAME }) do
          @lex_state = EXPR_BEG
          Token("~").set_text("~@")
        end

        @OP.def_rule("(") do
          @indent += 1
            # if @lex_state == EXPR_BEG || @lex_state == EXPR_MID
            #  @lex_state = EXPR_BEG
            #  tk = Token(TkfLPAREN)
            # else
            @lex_state = EXPR_BEG
            tk = Token(TkLPAREN)
          # end
          tk.set_text("(")
        end

        @OP.def_rule("[]", proc { @lex_state == EXPR_FNAME }) do
          Token("[]").set_text("[]")
        end

        @OP.def_rule("[]=", proc { @lex_state == EXPR_FNAME }) do
          Token("[]=").set_text("[]=")
        end

        @OP.def_rule("[") do
          @indent += 1
          # if @lex_state == EXPR_FNAME
          #   t = Token(TkfLBRACK)
          # else
          #   if @lex_state == EXPR_BEG || @lex_state == EXPR_MID
          #     t = Token(TkLBRACK)
          #   elsif @lex_state == EXPR_ARG && @space_seen
          #   else
          #     t = Token(TkfLBRACK)
          #   end
          # end
          t = Token(TkLBRACK)
          @lex_state = EXPR_BEG
          t.set_text("[")
        end

        @OP.def_rule("{") do
          @indent += 1
          # if @lex_state != EXPR_END && @lex_state != EXPR_ARG
          #   t = Token(TkLBRACE)
          # else
          #   t = Token(TkfLBRACE)
          # end
          t = Token(TkLBRACE)
          @lex_state = EXPR_BEG
          t.set_text("{")
        end

        @OP.def_rule('\\') do #'
          if getc == "\n"
            @space_seen = true
            @continue = true
            Token(TkSPACE).set_text("\\\n")
          else
            ungetc
            Token("\\").set_text("\\") #"
          end
        end

        @OP.def_rule('%') do |_op, _io|
          if @lex_state == EXPR_BEG || @lex_state == EXPR_MID
            identify_quotation('%')
          elsif peek(0) == '='
            getc
            Token(TkOPASGN, "%").set_text("%=")
          elsif @lex_state == EXPR_ARG && @space_seen && peek(0) !~ /\s/
            identify_quotation('%')
          else
            @lex_state = EXPR_BEG
            Token("%").set_text("%")
          end
        end

        @OP.def_rule('$') do #'
          identify_gvar
        end

        @OP.def_rule('@') do
          if peek(0) =~ /[@\w]/
            ungetc
            identify_identifier
          else
            Token("@").set_text("@")
          end
        end

        # @OP.def_rule("def", proc{|op, io| /\s/ =~ io.peek(0)}) do
        #   |op, io|
        #   @indent += 1
        #   @lex_state = EXPR_FNAME
        # # @lex_state = EXPR_END
        # # until @rests[0] == "\n" or @rests[0] == ";"
        # #   rests.shift
        # # end
        # end

        @OP.def_rule("__END__", proc { @prev_char_no == 0 && peek(0) =~ /[\r\n]/ }) do
          throw :eof
        end

        @OP.def_rule("") do |op, io|
          printf "MATCH: start %s: %s\n", op, io.inspect if RubyLex.debug?
          if peek(0) =~ /[0-9]/
            t = identify_number("")
          elsif peek(0) =~ /[\w]/
            t = identify_identifier
          end
          printf "MATCH: end %s: %s\n", op, io.inspect if RubyLex.debug?
          t
        end

        p @OP if RubyLex.debug?
      end

      def identify_gvar
        @lex_state = EXPR_END
        str = String.new("$")

        tk = case ch = getc
             when %r{[~_*$?!@/\\;,=:<>".]}
               str << ch
               Token(TkGVAR, str)

             when "-"
               str << "-" << getc
               Token(TkGVAR, str)

             when "&", "`", "'", "+"
               str << ch
               Token(TkBACK_REF, str)

             when /[1-9]/
               str << ch
               while (ch = getc) =~ /[0-9]/
                 str << ch
               end
               ungetc
               Token(TkNTH_REF)
             when /\w/
               ungetc
               ungetc
               return identify_identifier
             else
               ungetc
               Token("$")
             end
        tk.set_text(str)
      end

      def identify_identifier
        token = ""
        token.concat getc if peek(0) =~ /[$@]/
        token.concat getc if peek(0) == "@"

        while (ch = getc) =~ /\w|_/
          print ":", ch, ":" if RubyLex.debug?
          token.concat ch
        end
        ungetc

        if ch == "!" || ch == "?"
          token.concat getc
        end
        # fix token

        # $stderr.puts "identifier - #{token}, state = #@lex_state"

        case token
        when /^\$/
          return Token(TkGVAR, token).set_text(token)
        when /^\@/
          @lex_state = EXPR_END
          return Token(TkIVAR, token).set_text(token)
        end

        if @lex_state != EXPR_DOT
          print token, "\n" if RubyLex.debug?

          token_c, *trans = TkReading2Token[token]
          if token_c
            # reserved word?

            if @lex_state != EXPR_BEG &&
               @lex_state != EXPR_FNAME &&
               trans[1]
              # modifiers
              token_c = TkSymbol2Token[trans[1]]
              @lex_state = trans[0]
            else
              if @lex_state != EXPR_FNAME
                if ENINDENT_CLAUSE.include?(token)
                  @indent += 1

                  if ACCEPTS_COLON.include?(token)
                    @colonblock_seen = true
                  else
                    @colonblock_seen = false
                  end
                elsif DEINDENT_CLAUSE.include?(token)
                  @indent -= 1
                  @colonblock_seen = false
                end
                @lex_state = trans[0]
              else
                @lex_state = EXPR_END
              end
            end
            return Token(token_c, token).set_text(token)
          end
        end

        if @lex_state == EXPR_FNAME
          @lex_state = EXPR_END
          if peek(0) == '='
            token.concat getc
          end
        elsif @lex_state == EXPR_BEG || @lex_state == EXPR_DOT
          @lex_state = EXPR_ARG
        else
          @lex_state = EXPR_END
        end

        if token[0, 1] =~ /[A-Z]/
          return Token(TkCONSTANT, token).set_text(token)
        elsif token[token.size - 1, 1] =~ /[!?]/
          return Token(TkFID, token).set_text(token)
        else
          return Token(TkIDENTIFIER, token).set_text(token)
        end
      end

      def identify_here_document
        ch = getc
        if ch == "-"
          ch = getc
          indent = true
        end
        if /['"`]/ =~ ch # '
          lt = ch
          quoted = ""
          while (c = getc) && c != lt
            quoted.concat c
          end
        else
          lt = '"'
          quoted = ch.dup
          while (c = getc) && c =~ /\w/
            quoted.concat c
          end
          ungetc
        end

        ltback, @ltype = @ltype, lt
        reserve = String.new

        while ch = getc
          reserve << ch
          if ch == "\\" #"
            ch = getc
            reserve << ch
          elsif ch == "\n"
            break
          end
        end

        str = String.new
        while (l = gets)
          l.chomp!
          l.strip! if indent
          break if l == quoted
          str << l.chomp << "\n"
        end

        @reader.divert_read_from(reserve)

        @ltype = ltback
        @lex_state = EXPR_END
        Token(Ltype2Token[lt], str).set_text(str.dump)
      end

      def identify_quotation(initial_char)
        ch = getc
        if lt = PERCENT_LTYPE[ch]
          initial_char += ch
          ch = getc
        elsif ch =~ /\W/
          lt = "\""
        else
          # RubyLex.fail SyntaxError, "unknown type of %string ('#{ch}')"
        end
        # if ch !~ /\W/
        #   ungetc
        #   next
        # end
        # @ltype = lt
        @quoted = ch unless @quoted = PERCENT_PAREN[ch]
        identify_string(lt, @quoted, ch, initial_char) if lt
      end

      def identify_number(start)
        str = start.dup

        if start == "+" || start == "-" || start == ""
          start = getc
          str << start
        end

        @lex_state = EXPR_END

        if start == "0"
          if peek(0) == "x"
            ch = getc
            str << ch
            match = /[0-9a-f_]/
          else
            match = /[0-7_]/
          end
          while ch = getc
            if ch !~ match
              ungetc
              break
            else
              str << ch
            end
          end
          return Token(TkINTEGER).set_text(str)
        end

        type = TkINTEGER
        allow_point = true
        allow_e = true
        while ch = getc
          case ch
          when /[0-9_]/
            str << ch

          when allow_point && "."
            type = TkFLOAT
            if peek(0) !~ /[0-9]/
              ungetc
              break
            end
            str << ch
            allow_point = false

          when allow_e && "e", allow_e && "E"
            str << ch
            type = TkFLOAT
            if peek(0) =~ /[+-]/
              str << getc
            end
            allow_e = false
            allow_point = false
          else
            ungetc
            break
          end
        end
        Token(type).set_text(str)
      end

      def identify_string(ltype, quoted = ltype, opener = nil, initial_char = nil)
        @ltype = ltype
        @quoted = quoted
        subtype = nil

        str = String.new
        str << initial_char if initial_char
        str << (opener || quoted)

        nest = 0
        begin
          while ch = getc
            str << ch
            if @quoted == ch
              if nest == 0
                break
              else
                nest -= 1
              end
            elsif opener == ch
              nest += 1
            elsif @ltype != "'" && @ltype != "]" && ch == "#"
              ch = getc
              if ch == "{"
                subtype = true
                str << ch << skip_inner_expression
              else
                ungetc(ch)
              end
            elsif ch == '\\' #'
              str << read_escape
            end
          end
          if @ltype == "/"
            if peek(0) =~ /i|o|n|e|s/
              str << getc
            end
          end
          if subtype
            Token(DLtype2Token[ltype], str)
          else
            Token(Ltype2Token[ltype], str)
          end.set_text(str)
        ensure
          @ltype = nil
          @quoted = nil
          @lex_state = EXPR_END
        end
      end

      def skip_inner_expression
        res = String.new
        nest = 0
        while (ch = getc)
          res << ch
          if ch == '}'
            break if nest == 0
            nest -= 1
          elsif ch == '{'
            nest += 1
          end
        end
        res
      end

      def identify_comment
        @ltype = "#"
        comment = String.new("#")
        while ch = getc
          if ch == "\\"
            ch = getc
            if ch == "\n"
              ch = " "
            else
              comment << "\\"
            end
          else
            if ch == "\n"
              @ltype = nil
              ungetc
              break
            end
          end
          comment << ch
        end
        Token(TkCOMMENT).set_text(comment)
      end

      def read_escape
        res = String.new
        case ch = getc
        when /[0-7]/
          ungetc ch
          3.times do
          case ch = getc
          when /[0-7]/
          when nil
            break
          else
            ungetc
            break
          end
          res << ch
          end

        when "x"
          res << ch
          2.times do
          case ch = getc
          when /[0-9a-fA-F]/
          when nil
            break
          else
            ungetc
            break
          end
            res << ch
          end

        when "M"
          res << ch
          if (ch = getc) != '-'
            ungetc
          else
            res << ch
            if (ch = getc) == "\\" #"
              res << ch
              res << read_escape
            else
              res << ch
            end
          end

        when "C", "c" #, "^"
          res << ch
          if ch == "C" && (ch = getc) != "-"
            ungetc
          else
            res << ch
            if (ch = getc) == "\\" #"
              res << ch
              res << read_escape
            else
              res << ch
            end
          end
        else
          res << ch
        end
        res
      end
    end
  end
end
