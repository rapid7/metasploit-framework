module Thin
  # Store HTTP header name-value pairs direcly to a string
  # and allow duplicated entries on some names.
  class Headers
    HEADER_FORMAT      = "%s: %s\r\n".freeze
    ALLOWED_DUPLICATES = %w(set-cookie set-cookie2 warning www-authenticate).freeze
    
    def initialize
      @sent = {}
      @out = []
    end
    
    # Add <tt>key: value</tt> pair to the headers.
    # Ignore if already sent and no duplicates are allowed
    # for this +key+.
    def []=(key, value)
      downcase_key = key.downcase
      if !@sent.has_key?(downcase_key) || ALLOWED_DUPLICATES.include?(downcase_key)
        @sent[downcase_key] = true
        value = case value
                when Time
                  value.httpdate
                when NilClass
                  return
                else
                  value.to_s
                end
        @out << HEADER_FORMAT % [key, value]
      end
    end
    
    def has_key?(key)
      @sent[key.downcase]
    end
    
    def to_s
      @out.join
    end
  end
end
