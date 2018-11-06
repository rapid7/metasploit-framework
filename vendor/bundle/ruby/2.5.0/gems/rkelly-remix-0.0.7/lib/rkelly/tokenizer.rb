# -*- coding: utf-8 -*-
require 'rkelly/lexeme'
require 'rkelly/char_range'
require 'strscan'

module RKelly
  class Tokenizer
    KEYWORDS = Hash[%w{
      break case catch continue default delete do else finally for function
      if in instanceof new return switch this throw try typeof var void while
      with

      const true false null debugger
    }.map {|kw| [kw, kw.upcase.to_sym] }]

    # These 6 are always reserved in ECMAScript 5.1
    # Some others are only reserved in strict mode, but RKelly doesn't
    # differenciate between strict and non-strict mode code.
    # http://www.ecma-international.org/ecma-262/5.1/#sec-7.6.1.2
    # https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Reserved_Words
    RESERVED = Hash[%w{
      class enum export extends import super
    }.map {|kw| [kw, true] }]

    LITERALS = {
      # Punctuators
      '=='  => :EQEQ,
      '!='  => :NE,
      '===' => :STREQ,
      '!==' => :STRNEQ,
      '<='  => :LE,
      '>='  => :GE,
      '||'  => :OR,
      '&&'  => :AND,
      '++'  => :PLUSPLUS,
      '--'  => :MINUSMINUS,
      '<<'  => :LSHIFT,
      '<<=' => :LSHIFTEQUAL,
      '>>'  => :RSHIFT,
      '>>=' => :RSHIFTEQUAL,
      '>>>' => :URSHIFT,
      '>>>='=> :URSHIFTEQUAL,
      '&='  => :ANDEQUAL,
      '%='  => :MODEQUAL,
      '^='  => :XOREQUAL,
      '|='  => :OREQUAL,
      '+='  => :PLUSEQUAL,
      '-='  => :MINUSEQUAL,
      '*='  => :MULTEQUAL,
      '/='  => :DIVEQUAL,
    }

    # Some keywords can be followed by regular expressions (eg, return and throw).
    # Others can be followed by division.
    KEYWORDS_THAT_IMPLY_DIVISION = {
      'this' => true,
      'true' => true,
      'false' => true,
      'null' => true,
    }

    KEYWORDS_THAT_IMPLY_REGEX = KEYWORDS.reject {|k,v| KEYWORDS_THAT_IMPLY_DIVISION[k] }

    SINGLE_CHARS_THAT_IMPLY_DIVISION = {
      ')' => true,
      ']' => true,
      '}' => true,
    }

    # Determine the method to use to measure String length in bytes,
    # because StringScanner#pos can only be set in bytes.
    #
    # - In Ruby 1.8 String#length returns always the string length
    #   in bytes.
    #
    # - In Ruby 1.9+ String#length returns string length in
    #   characters and we need to use String#bytesize instead.
    #
    BYTESIZE_METHOD = "".respond_to?(:bytesize) ? :bytesize : :length

    # JavaScript whitespace can consist of any Unicode space separator
    # characters.
    #
    # - In Ruby 1.9+ we can just use the [[:space:]] character class
    #   and match them all.
    #
    # - In Ruby 1.8 we need a regex that identifies the specific bytes
    #   in UTF-8 text.
    #
    WHITESPACE_REGEX = "".respond_to?(:encoding) ? /[[:space:]]+/m : %r{
      (
        \xC2\xA0     |   # no-break space
        \xE1\x9A\x80 |   # ogham space mark
        \xE2\x80\x80 |   # en quad
        \xE2\x80\x81 |   # em quad
        \xE2\x80\x82 |   # en space
        \xE2\x80\x83 |   # em space
        \xE2\x80\x84 |   # three-per-em space
        \xE2\x80\x85 |   # four-pre-em süace
        \xE2\x80\x86 |   # six-per-em space
        \xE2\x80\x87 |   # figure space
        \xE2\x80\x88 |   # punctuation space
        \xE2\x80\x89 |   # thin space
        \xE2\x80\x8A |   # hair space
        \xE2\x80\xA8 |   # line separator
        \xE2\x80\xA9 |   # paragraph separator
        \xE2\x80\xAF |   # narrow no-break space
        \xE2\x81\x9F |   # medium mathematical space
        \xE3\x80\x80     # ideographic space
      )+
    }mx

    def initialize(&block)
      @lexemes = Hash.new {|hash, key| hash[key] = [] }

      token(:COMMENT, /\/(?:\*(?:.)*?\*\/|\/[^\n]*)/m, ['/'])
      token(:STRING, /"(?:[^"\\]*(?:\\.[^"\\]*)*)"|'(?:[^'\\]*(?:\\.[^'\\]*)*)'/m, ["'", '"'])

      # Matcher for basic ASCII whitespace.
      # (Unicode whitespace is handled separately in #match_lexeme)
      #
      # Can't use just "\s" in regex, because in Ruby 1.8 this
      # doesn't include the vertical tab "\v" character
      token(:S, /[ \t\r\n\f\v]*/m, [" ", "\t", "\r", "\n", "\f", "\v"])

      # A regexp to match floating point literals (but not integer literals).
      digits = ('0'..'9').to_a
      token(:NUMBER, /\d+\.\d*(?:[eE][-+]?\d+)?|\d+(?:\.\d*)?[eE][-+]?\d+|\.\d+(?:[eE][-+]?\d+)?/m, digits+['.']) do |type, value|
        value.gsub!(/\.(\D)/, '.0\1') if value =~ /\.\w/
        value.gsub!(/\.$/, '.0') if value =~ /\.$/
        value.gsub!(/^\./, '0.') if value =~ /^\./
        [type, eval(value)]
      end
      token(:NUMBER, /0[xX][\da-fA-F]+|0[0-7]*|\d+/, digits) do |type, value|
        [type, eval(value)]
      end

      word_chars = ('a'..'z').to_a + ('A'..'Z').to_a + ['_', '$']
      token(:RAW_IDENT, /([_\$A-Za-z][_\$0-9A-Za-z]*)/, word_chars) do |type,value|
        if KEYWORDS[value]
          [KEYWORDS[value], value]
        elsif RESERVED[value]
          [:RESERVED, value]
        else
          [:IDENT, value]
        end
      end

      # To distinguish regular expressions from comments, we require that
      # regular expressions start with a non * character (ie, not look like
      # /*foo*/). Note that we can't depend on the length of the match to
      # correctly distinguish, since `/**/i` is longer if matched as a regular
      # expression than as matched as a comment.
      # Incidentally, we're also not matching empty regular expressions
      # (eg, // and //g). Here we could depend on match length and priority to
      # determine that these are actually comments, but it turns out to be
      # easier to not match them in the first place.
      token(:REGEXP, %r{
             /                  (?# beginning )

             (?:
               [^\r\n\[/\\]+      (?# any char except \r \n [ / \ )
               |
               \\ [^\r\n]         (?# escape sequence )
               |
               \[ (?:[^\]\\]|\\.)* \]   (?# [...] can contain any char including / )
                                        (?# only \ and ] have to be escaped here )
             )+

             /[gim]*            (?# ending + modifiers )
      }x, ['/'])

      literal_chars = LITERALS.keys.map {|k| k.slice(0,1) }.uniq
      literal_regex = Regexp.new(LITERALS.keys.sort_by { |x|
          x.length
        }.reverse.map { |x| "#{x.gsub(/([|+*^])/, '\\\\\1')}" }.join('|'))
      token(:LITERALS, literal_regex, literal_chars) do |type, value|
        [LITERALS[value], value]
      end

      symbols = ('!'..'/').to_a + (':'..'@').to_a + ('['..'^').to_a + ['`'] + ('{'..'~').to_a
      token(:SINGLE_CHAR, /./, symbols) do |type, value|
        [value, value]
      end
    end

    def tokenize(string)
      raw_tokens(string).map { |x| x.to_racc_token }
    end

    def raw_tokens(string)
      scanner = StringScanner.new(string)
      tokens = []
      range = CharRange::EMPTY
      accepting_regexp = true
      while !scanner.eos?
        token = match_lexeme(scanner, accepting_regexp)

        if token.name != :S
          accepting_regexp = followable_by_regex(token)
        end

        scanner.pos += token.value.send(BYTESIZE_METHOD)
        token.range = range = range.next(token.value)
        tokens << token
      end
      tokens
    end

    private

    # Returns the token of the first matching lexeme
    def match_lexeme(scanner, accepting_regexp)
      @lexemes[scanner.peek(1)].each do |lexeme|
        next if lexeme.name == :REGEXP && !accepting_regexp

        token = lexeme.match(scanner)
        return token if token
      end

      # When some other character encountered, try to match it as
      # whitespace, as in JavaScript whitespace can contain any
      # Unicode whitespace character.
      if str = scanner.check(WHITESPACE_REGEX)
        return Token.new(:S, str)
      end
    end

    # Registers a lexeme and maps it to all the characters it can
    # begin with.  So later when scanning the source we only need to
    # match those lexemes that can begin with the character we're at.
    def token(name, pattern, chars, &block)
      lexeme = Lexeme.new(name, pattern, &block)
      chars.each do |c|
        @lexemes[c] << lexeme
      end
    end

    def followable_by_regex(current_token)
      case current_token.name
      when :RAW_IDENT
        KEYWORDS_THAT_IMPLY_REGEX[current_token.value]
      when :NUMBER
        false
      when :SINGLE_CHAR
        !SINGLE_CHARS_THAT_IMPLY_DIVISION[current_token.value]
      else
        true
      end
    end
  end
end
