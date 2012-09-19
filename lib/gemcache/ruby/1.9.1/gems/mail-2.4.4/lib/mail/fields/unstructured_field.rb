# encoding: utf-8
require 'mail/fields/common/common_field'

module Mail
  # Provides access to an unstructured header field
  #
  # ===Per RFC 2822:
  #  2.2.1. Unstructured Header Field Bodies
  #  
  #     Some field bodies in this standard are defined simply as
  #     "unstructured" (which is specified below as any US-ASCII characters,
  #     except for CR and LF) with no further restrictions.  These are
  #     referred to as unstructured field bodies.  Semantically, unstructured
  #     field bodies are simply to be treated as a single line of characters
  #     with no further processing (except for header "folding" and
  #     "unfolding" as described in section 2.2.3).
  class UnstructuredField
    
    include Mail::CommonField
    include Mail::Utilities
   
    attr_accessor :charset
    attr_reader :errors
 
    def initialize(name, value, charset = nil)
      @errors = []
      if charset
        self.charset = charset
      else
        if value.to_s.respond_to?(:encoding)
          self.charset = value.to_s.encoding
        else
          self.charset = $KCODE
        end
      end
      self.name = name
      self.value = value
      self
    end
   
    def encoded
      do_encode
    end
    
    def decoded
      do_decode
    end

    def default
      decoded
    end
    
    def parse # An unstructured field does not parse
      self
    end

    private
    
    def do_encode
      value.nil? ? '' : "#{wrapped_value}\r\n"
    end
    
    def do_decode
      result = value.blank? ? nil : Encodings.decode_encode(value, :decode)
      result.encode!(value.encoding || "UTF-8") if RUBY_VERSION >= '1.9' && !result.blank?
      result
    end
    
    # 2.2.3. Long Header Fields
    # 
    #  Each header field is logically a single line of characters comprising
    #  the field name, the colon, and the field body.  For convenience
    #  however, and to deal with the 998/78 character limitations per line,
    #  the field body portion of a header field can be split into a multiple
    #  line representation; this is called "folding".  The general rule is
    #  that wherever this standard allows for folding white space (not
    #  simply WSP characters), a CRLF may be inserted before any WSP.  For
    #  example, the header field:
    #  
    #          Subject: This is a test
    #  
    #  can be represented as:
    #  
    #          Subject: This
    #           is a test
    #  
    #  Note: Though structured field bodies are defined in such a way that
    #  folding can take place between many of the lexical tokens (and even
    #  within some of the lexical tokens), folding SHOULD be limited to
    #  placing the CRLF at higher-level syntactic breaks.  For instance, if
    #  a field body is defined as comma-separated values, it is recommended
    #  that folding occur after the comma separating the structured items in
    #  preference to other places where the field could be folded, even if
    #  it is allowed elsewhere.
    def wrapped_value # :nodoc:
      wrap_lines(name, fold("#{name}: ".length))
    end
   
    # 6.2. Display of 'encoded-word's
    # 
    #  When displaying a particular header field that contains multiple
    #  'encoded-word's, any 'linear-white-space' that separates a pair of
    #  adjacent 'encoded-word's is ignored.  (This is to allow the use of
    #  multiple 'encoded-word's to represent long strings of unencoded text,
    #  without having to separate 'encoded-word's where spaces occur in the
    #  unencoded text.)
    def wrap_lines(name, folded_lines)
      result = ["#{name}: #{folded_lines.shift}"]
      result.concat(folded_lines)
      result.join("\r\n\s")
    end

    def fold(prepend = 0) # :nodoc:
      encoding       = normalized_encoding
      decoded_string = decoded.to_s
      should_encode  = decoded_string.not_ascii_only?
      if should_encode
        first = true
        words = decoded_string.split(/[ \t]/).map do |word|
          if first
            first = !first
          else
            word = " " << word
          end
          if word.not_ascii_only?
            word
          else
            word.scan(/.{7}|.+$/)
          end
        end.flatten
      else
        words = decoded_string.split(/[ \t]/)
      end
      
      folded_lines   = []
      while !words.empty?
        limit = 78 - prepend
        limit = limit - 7 - encoding.length if should_encode
        line = ""
        while !words.empty?
          break unless word = words.first.dup
          word.encode!(charset) if defined?(Encoding) && charset
          word = encode(word) if should_encode
          word = encode_crlf(word)
          # Skip to next line if we're going to go past the limit
          # Unless this is the first word, in which case we're going to add it anyway
          # Note: This means that a word that's longer than 998 characters is going to break the spec. Please fix if this is a problem for you.
          # (The fix, it seems, would be to use encoded-word encoding on it, because that way you can break it across multiple lines and 
          # the linebreak will be ignored)
          break if !line.empty? && (line.length + word.length + 1 > limit)
          # Remove the word from the queue ...
          words.shift
          # Add word separator
          line << " " unless (line.empty? || should_encode)
          # ... add it in encoded form to the current line
          line << word          
        end
        # Encode the line if necessary
        line = "=?#{encoding}?Q?#{line}?=" if should_encode
        # Add the line to the output and reset the prepend
        folded_lines << line
        prepend = 0
      end
      folded_lines
    end
 
    def encode(value)
      value = [value].pack("M").gsub("=\n", '')
      value.gsub!(/"/,  '=22')
      value.gsub!(/\(/, '=28')
      value.gsub!(/\)/, '=29')
      value.gsub!(/\?/, '=3F')
      value.gsub!(/_/,  '=5F')
      value.gsub!(/ /,  '_')
      value
    end

    def encode_crlf(value)
      value.gsub!("\r", '=0D')
      value.gsub!("\n", '=0A')
      value
    end

    def normalized_encoding
      encoding = charset.to_s.upcase.gsub('_', '-')
      encoding = 'UTF-8' if encoding == 'UTF8' # Ruby 1.8.x and $KCODE == 'u'
      encoding
    end

  end
end
