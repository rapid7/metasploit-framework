module CodeRay
module Scanners
  
  # Scanner for YAML.
  #
  # Based on the YAML scanner from Syntax by Jamis Buck.
  class YAML < Scanner
    
    register_for :yaml
    file_extension 'yml'
    
    KINDS_NOT_LOC = :all
    
  protected
    
    def scan_tokens encoder, options
      
      state = :initial
      key_indent = string_indent = 0
      
      until eos?
        
        key_indent = nil if bol?
        
        if match = scan(/ +[\t ]*/)
          encoder.text_token match, :space
          
        elsif match = scan(/\n+/)
          encoder.text_token match, :space
          state = :initial if match.index(?\n)
          
        elsif match = scan(/#.*/)
          encoder.text_token match, :comment
          
        elsif bol? and case
          when match = scan(/---|\.\.\./)
            encoder.begin_group :head
            encoder.text_token match, :head
            encoder.end_group :head
            next
          when match = scan(/%.*/)
            encoder.text_token match, :doctype
            next
          end
        
        elsif state == :value and case
          when !check(/(?:"[^"]*")(?=: |:$)/) && match = scan(/"/)
            encoder.begin_group :string
            encoder.text_token match, :delimiter
            encoder.text_token match, :content if match = scan(/ [^"\\]* (?: \\. [^"\\]* )* /mx)
            encoder.text_token match, :delimiter if match = scan(/"/)
            encoder.end_group :string
            next
          when match = scan(/[|>][-+]?/)
            encoder.begin_group :string
            encoder.text_token match, :delimiter
            string_indent = key_indent || column(pos - match.size) - 1
            encoder.text_token matched, :content if scan(/(?:\n+ {#{string_indent + 1}}.*)+/)
            encoder.end_group :string
            next
          when match = scan(/(?![!"*&]).+?(?=$|\s+#)/)
            encoder.begin_group :string
            encoder.text_token match, :content
            string_indent = key_indent || column(pos - match.size) - 1
            encoder.text_token matched, :content if scan(/(?:\n+ {#{string_indent + 1}}.*)+/)
            encoder.end_group :string
            next
          end
          
        elsif case
          when match = scan(/[-:](?= |$)/)
            state = :value if state == :colon && (match == ':' || match == '-')
            state = :value if state == :initial && match == '-'
            encoder.text_token match, :operator
            next
          when match = scan(/[,{}\[\]]/)
            encoder.text_token match, :operator
            next
          when state == :initial && match = scan(/[-\w.()\/ ]*\S(?= *:(?: |$))/)
            encoder.text_token match, :key
            key_indent = column(pos - match.size) - 1
            state = :colon
            next
          when match = scan(/(?:"[^"\n]*"|'[^'\n]*')(?= *:(?: |$))/)
            encoder.begin_group :key
            encoder.text_token match[0,1], :delimiter
            encoder.text_token match[1..-2], :content
            encoder.text_token match[-1,1], :delimiter
            encoder.end_group :key
            key_indent = column(pos - match.size) - 1
            state = :colon
            next
          when match = scan(/(![\w\/]+)(:([\w:]+))?/)
            encoder.text_token self[1], :type
            if self[2]
              encoder.text_token ':', :operator
              encoder.text_token self[3], :class
            end
            next
          when match = scan(/&\S+/)
            encoder.text_token match, :variable
            next
          when match = scan(/\*\w+/)
            encoder.text_token match, :global_variable
            next
          when match = scan(/<</)
            encoder.text_token match, :class_variable
            next
          when match = scan(/\d\d:\d\d:\d\d/)
            encoder.text_token match, :octal
            next
          when match = scan(/\d\d\d\d-\d\d-\d\d\s\d\d:\d\d:\d\d(\.\d+)? [-+]\d\d:\d\d/)
            encoder.text_token match, :octal
            next
          when match = scan(/:\w+/)
            encoder.text_token match, :symbol
            next
          when match = scan(/[^:\s]+(:(?! |$)[^:\s]*)* .*/)
            encoder.text_token match, :error
            next
          when match = scan(/[^:\s]+(:(?! |$)[^:\s]*)*/)
            encoder.text_token match, :error
            next
          end
          
        else
          raise if eos?
          encoder.text_token getch, :error
          
        end
        
      end
      
      encoder
    end
    
  end
  
end
end
