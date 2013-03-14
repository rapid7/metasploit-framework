# encoding: utf-8
module Mail
  class EnvelopeFromElement
    
    include Mail::Utilities
    
    def initialize( string )
      parser = Mail::EnvelopeFromParser.new
      if @tree = parser.parse(string)
        @address = tree.addr_spec.text_value.strip
        @date_time = ::DateTime.parse("#{tree.ctime_date.text_value}")
      else
        raise Mail::Field::ParseError.new(EnvelopeFromElement, string, parser.failure_reason)
      end
    end
    
    def tree
      @tree
    end
    
    def date_time
      @date_time
    end
    
    def address
      @address
    end
    
    def to_s(*args)
      "#{@info}; #{@date_time.to_s(*args)}"
    end
    
  end
end
