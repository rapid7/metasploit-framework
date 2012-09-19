require 'windows/unicode'
require 'windows/msvcrt/string'

# This is a class that simplifies wide string handling. It is NOT meant
# for general consumption, but for internal use by the Win32Utils Team.
# Use at your own risk.
# 
class WideString < String
   include Windows::Unicode
   include Windows::MSVCRT::String
   
   ACP  = CP_ACP
   UTF7 = CP_UTF7
   UTF8 = CP_UTF8
   
   # Get or set the encoding of the wide string object
   #
   attr_accessor :encoding
   
   # Creates a new wide +string+ with the given +encoding+, or UTF8 if
   # no encoding is specified.
   #
   def initialize(string, encoding = UTF8)
      super(multi_to_wide(string, encoding))
      @encoding = encoding
   end
   
   # Returns the multibyte version of the wide string.
   #
   def to_multi
      wide_to_multi(self, @encoding)      
   end

   # Replaces the wide string with a multibyte version.
   #   
   def to_multi!
      self.replace(wide_to_multi(self, @encoding))  
   end
   
   alias to_s to_multi
   alias to_str to_multi
   alias inspect to_multi
   
   # Strips the trailing two null characters from the string.
   #
   def wstrip
      self[0..-3] if string[-2..-1] == "\000\000"
   end
   
   # The length of the wide string in chars.
   #
   def length
      wcslen(self) * 2      
   end
   
   # The size of the wide string in bytes.
   def size
      wcslen(self)      
   end   
end