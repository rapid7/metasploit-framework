RSpec::Support.require_rspec_support 'source/location'

module RSpec
  module Support
    class Source
      # @private
      # A wrapper for Ripper token which is generated with `Ripper.lex`.
      class Token
        CLOSING_TYPES_BY_OPENING_TYPE = {
          :on_lbracket    => :on_rbracket,
          :on_lparen      => :on_rparen,
          :on_lbrace      => :on_rbrace,
          :on_heredoc_beg => :on_heredoc_end
        }.freeze

        CLOSING_KEYWORDS_BY_OPENING_KEYWORD = {
          'def' => 'end',
          'do'  => 'end',
        }.freeze

        attr_reader :token

        def self.tokens_from_ripper_tokens(ripper_tokens)
          ripper_tokens.map { |ripper_token| new(ripper_token) }.freeze
        end

        def initialize(ripper_token)
          @token = ripper_token.freeze
        end

        def location
          @location ||= Location.new(*token[0])
        end

        def type
          token[1]
        end

        def string
          token[2]
        end

        def ==(other)
          token == other.token
        end

        alias_method :eql?, :==

        def inspect
          "#<#{self.class} #{type} #{string.inspect}>"
        end

        def keyword?
          type == :on_kw
        end

        def opening?
          opening_delimiter? || opening_keyword?
        end

        def closed_by?(other)
          closed_by_delimiter?(other) || closed_by_keyword?(other)
        end

      private

        def opening_delimiter?
          CLOSING_TYPES_BY_OPENING_TYPE.key?(type)
        end

        def opening_keyword?
          return false unless keyword?
          CLOSING_KEYWORDS_BY_OPENING_KEYWORD.key?(string)
        end

        def closed_by_delimiter?(other)
          other.type == CLOSING_TYPES_BY_OPENING_TYPE[type]
        end

        def closed_by_keyword?(other)
          return false unless other.keyword?
          other.string == CLOSING_KEYWORDS_BY_OPENING_KEYWORD[string]
        end
      end
    end
  end
end
