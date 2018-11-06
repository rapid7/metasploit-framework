require 'rkelly/tokenizer'
require 'rkelly/generated_parser'


module RKelly
  class Parser < RKelly::GeneratedParser
    TOKENIZER = Tokenizer.new

    RKelly::GeneratedParser.instance_methods.each do |im|
      next unless im.to_s =~ /^_reduce_\d+$/
      eval(<<-eoawesomehack)
        def #{im}(val, _values, result)
          r = super(val.map { |v|
              v.is_a?(Token) ? v.to_racc_token[1] : v
            }, _values, result)

          suitable_values = val.flatten.find_all {|v| v.is_a?(Node) || v.is_a?(Token) }
          first = suitable_values.first
          last = suitable_values.last
          if first
            r.range = CharRange.new(first.range.from, last.range.to) if r.respond_to?(:range)
            r.filename = @filename if r.respond_to?(:filename)
          end
          r
        end
      eoawesomehack
    end

    attr_accessor :logger
    def initialize
      @tokens = []
      @logger = nil
      @terminator = false
      @prev_token = nil
      @comments = []
    end

    # Parse +javascript+ and return an AST
    def parse(javascript, filename = nil)
      @tokens = TOKENIZER.raw_tokens(javascript)
      @position = 0
      @filename = filename
      ast = do_parse
      ast.comments = @comments if ast
      ast
    end

    def yyabort
      raise "something bad happened, please report a bug with sample JavaScript"
    end

    # When parsing finishes without all tokens being parsed, returns
    # the token at which the parsing stopped.  Returns nil when parser
    # reached to the very last token (but possibly still failed as it
    # expeced more tokens).
    #
    # Useful for pin-pointing the position of a syntax error.
    def stopped_at
      if @position < @tokens.length
        @tokens[@position-1]
      else
        nil
      end
    end

    private
    def on_error(error_token_id, error_value, value_stack)
      if logger
        logger.error(token_to_str(error_token_id))
        logger.error("error value: #{error_value}")
        logger.error("error stack: #{value_stack}")
      end
    end

    def next_token
      @terminator = false
      begin
        return [false, false] if @position >= @tokens.length
        n_token = @tokens[@position]
        @position += 1
        case @tokens[@position - 1].name
        when :COMMENT
          @comments << n_token
          @terminator = true if n_token.value =~ /^\/\//
        when :S
          @terminator = true if n_token.value =~ /[\r\n]/
        end
      end while([:COMMENT, :S].include?(n_token.name))

      if @terminator &&
          ((@prev_token && %w[continue break return throw].include?(@prev_token.value)) ||
           (n_token && %w[++ --].include?(n_token.value)))
        @position -= 1
        return (@prev_token = RKelly::Token.new(';', ';')).to_racc_token
      end

      @prev_token = n_token
      v = n_token.to_racc_token
      v[1] = n_token
      v
    end
  end
end
