##
# A TokenStream is a list of tokens, gathered during the parse of some entity
# (say a method). Entities populate these streams by being registered with the
# lexer. Any class can collect tokens by including TokenStream. From the
# outside, you use such an object by calling the start_collecting_tokens
# method, followed by calls to add_token and pop_token.

module RDoc::TokenStream

  ##
  # Converts +token_stream+ to HTML wrapping various tokens with
  # <tt><span></tt> elements.  The following tokens types are wrapped in spans
  # with the given class names:
  #
  # TkCONSTANT :: 'ruby-constant'
  # TkKW       :: 'ruby-keyword'
  # TkIVAR     :: 'ruby-ivar'
  # TkOp       :: 'ruby-operator'
  # TkId       :: 'ruby-identifier'
  # TkNode     :: 'ruby-node'
  # TkCOMMENT  :: 'ruby-comment'
  # TkREGEXP   :: 'ruby-regexp'
  # TkSTRING   :: 'ruby-string'
  # TkVal      :: 'ruby-value'
  #
  # Other token types are not wrapped in spans.

  def self.to_html token_stream
    token_stream.map do |t|
      next unless t

      style = case t
              when RDoc::RubyToken::TkCONSTANT then 'ruby-constant'
              when RDoc::RubyToken::TkKW       then 'ruby-keyword'
              when RDoc::RubyToken::TkIVAR     then 'ruby-ivar'
              when RDoc::RubyToken::TkOp       then 'ruby-operator'
              when RDoc::RubyToken::TkId       then 'ruby-identifier'
              when RDoc::RubyToken::TkNode     then 'ruby-node'
              when RDoc::RubyToken::TkCOMMENT  then 'ruby-comment'
              when RDoc::RubyToken::TkREGEXP   then 'ruby-regexp'
              when RDoc::RubyToken::TkSTRING   then 'ruby-string'
              when RDoc::RubyToken::TkVal      then 'ruby-value'
              end

      text = CGI.escapeHTML t.text

      if style then
        "<span class=\"#{style}\">#{text}</span>"
      else
        text
      end
    end.join
  end

  ##
  # Adds +tokens+ to the collected tokens

  def add_tokens(*tokens)
    tokens.flatten.each { |token| @token_stream << token }
  end

  alias add_token add_tokens

  ##
  # Starts collecting tokens

  def collect_tokens
    @token_stream = []
  end

  alias start_collecting_tokens collect_tokens

  ##
  # Remove the last token from the collected tokens

  def pop_token
    @token_stream.pop
  end

  ##
  # Current token stream

  def token_stream
    @token_stream
  end

  ##
  # Returns a string representation of the token stream

  def tokens_to_s
    token_stream.map { |token| token.text }.join ''
  end

end

