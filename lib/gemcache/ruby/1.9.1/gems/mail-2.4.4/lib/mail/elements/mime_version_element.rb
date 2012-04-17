# encoding: utf-8
module Mail
  class MimeVersionElement
    
    include Mail::Utilities
    
    def initialize( string )
      parser = Mail::MimeVersionParser.new
      if tree = parser.parse(string)
        @major = tree.major.text_value
        @minor = tree.minor.text_value
      else
        raise Mail::Field::ParseError.new(MimeVersionElement, string, parser.failure_reason)
      end
    end
    
    def major
      @major
    end
    
    def minor
      @minor
    end
    
  end
end
