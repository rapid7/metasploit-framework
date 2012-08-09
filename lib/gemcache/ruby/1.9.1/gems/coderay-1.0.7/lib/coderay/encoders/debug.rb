module CodeRay
module Encoders
  
  # = Debug Encoder
  #
  # Fast encoder producing simple debug output.
  #
  # It is readable and diff-able and is used for testing.
  #
  # You cannot fully restore the tokens information from the
  # output, because consecutive :space tokens are merged.
  # Use Tokens#dump for caching purposes.
  # 
  # See also: Scanners::Debug
  class Debug < Encoder
    
    register_for :debug
    
    FILE_EXTENSION = 'raydebug'
    
    def initialize options = {}
      super
      @opened = []
    end
    
    def text_token text, kind
      if kind == :space
        @out << text
      else
        # TODO: Escape (
        text = text.gsub(/[)\\]/, '\\\\\0')  # escape ) and \
        @out << kind.to_s << '(' << text << ')'
      end
    end
    
    def begin_group kind
      @opened << kind
      @out << kind.to_s << '<'
    end
    
    def end_group kind
      if @opened.last != kind
        puts @out
        raise "we are inside #{@opened.inspect}, not #{kind}"
      end
      @opened.pop
      @out << '>'
    end
    
    def begin_line kind
      @out << kind.to_s << '['
    end
    
    def end_line kind
      @out << ']'
    end
    
  end
  
end
end
