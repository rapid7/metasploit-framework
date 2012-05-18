module CodeRay
module Scanners

  # HTML Scanner
  # 
  # Alias: +xhtml+
  # 
  # See also: Scanners::XML
  class HTML < Scanner

    register_for :html
    
    KINDS_NOT_LOC = [
      :comment, :doctype, :preprocessor,
      :tag, :attribute_name, :operator,
      :attribute_value, :string,
      :plain, :entity, :error,
    ]  # :nodoc:
    
    EVENT_ATTRIBUTES = %w(
      onabort onafterprint onbeforeprint onbeforeunload onblur oncanplay
      oncanplaythrough onchange onclick oncontextmenu oncuechange ondblclick
      ondrag ondragdrop ondragend ondragenter ondragleave ondragover
      ondragstart ondrop ondurationchange onemptied onended onerror onfocus
      onformchange onforminput onhashchange oninput oninvalid onkeydown
      onkeypress onkeyup onload onloadeddata onloadedmetadata onloadstart
      onmessage onmousedown onmousemove onmouseout onmouseover onmouseup
      onmousewheel onmove onoffline ononline onpagehide onpageshow onpause
      onplay onplaying onpopstate onprogress onratechange onreadystatechange
      onredo onreset onresize onscroll onseeked onseeking onselect onshow
      onstalled onstorage onsubmit onsuspend ontimeupdate onundo onunload
      onvolumechange onwaiting
    )
    
    IN_ATTRIBUTE = WordList::CaseIgnoring.new(nil).
      add(EVENT_ATTRIBUTES, :script)
    
    ATTR_NAME = /[\w.:-]+/  # :nodoc:
    TAG_END = /\/?>/  # :nodoc:
    HEX = /[0-9a-fA-F]/  # :nodoc:
    ENTITY = /
      &
      (?:
        \w+
      |
        \#
        (?:
          \d+
        |
          x#{HEX}+
        )
      )
      ;
    /ox  # :nodoc:
    
    PLAIN_STRING_CONTENT = {
      "'" => /[^&'>\n]+/,
      '"' => /[^&">\n]+/,
    }  # :nodoc:
    
    def reset
      super
      @state = :initial
      @plain_string_content = nil
    end
    
  protected
    
    def setup
      @state = :initial
      @plain_string_content = nil
    end
    
    def scan_java_script encoder, code
      if code && !code.empty?
        @java_script_scanner ||= Scanners::JavaScript.new '', :keep_tokens => true
        # encoder.begin_group :inline
        @java_script_scanner.tokenize code, :tokens => encoder
        # encoder.end_group :inline
      end
    end
    
    def scan_tokens encoder, options
      state = options[:state] || @state
      plain_string_content = @plain_string_content
      in_tag = in_attribute = nil
      
      encoder.begin_group :string if state == :attribute_value_string
      
      until eos?
        
        if state != :in_special_tag && match = scan(/\s+/m)
          encoder.text_token match, :space
          
        else
          
          case state
          
          when :initial
            if match = scan(/<!--(?:.*?-->|.*)/m)
              encoder.text_token match, :comment
            elsif match = scan(/<!DOCTYPE(?:.*?>|.*)/m)
              encoder.text_token match, :doctype
            elsif match = scan(/<\?xml(?:.*?\?>|.*)/m)
              encoder.text_token match, :preprocessor
            elsif match = scan(/<\?(?:.*?\?>|.*)/m)
              encoder.text_token match, :comment
            elsif match = scan(/<\/[-\w.:]*>?/m)
              in_tag = nil
              encoder.text_token match, :tag
            elsif match = scan(/<(?:(script)|[-\w.:]+)(>)?/m)
              encoder.text_token match, :tag
              in_tag = self[1]
              if self[2]
                state = :in_special_tag if in_tag
              else
                state = :attribute
              end
            elsif match = scan(/[^<>&]+/)
              encoder.text_token match, :plain
            elsif match = scan(/#{ENTITY}/ox)
              encoder.text_token match, :entity
            elsif match = scan(/[<>&]/)
              in_tag = nil
              encoder.text_token match, :error
            else
              raise_inspect '[BUG] else-case reached with state %p' % [state], encoder
            end
            
          when :attribute
            if match = scan(/#{TAG_END}/o)
              encoder.text_token match, :tag
              in_attribute = nil
              if in_tag
                state = :in_special_tag
              else
                state = :initial
              end
            elsif match = scan(/#{ATTR_NAME}/o)
              in_attribute = IN_ATTRIBUTE[match]
              encoder.text_token match, :attribute_name
              state = :attribute_equal
            else
              in_tag = nil
              encoder.text_token getch, :error
            end
            
          when :attribute_equal
            if match = scan(/=/)  #/
              encoder.text_token match, :operator
              state = :attribute_value
            elsif scan(/#{ATTR_NAME}/o) || scan(/#{TAG_END}/o)
              state = :attribute
              next
            else
              encoder.text_token getch, :error
              state = :attribute
            end
            
          when :attribute_value
            if match = scan(/#{ATTR_NAME}/o)
              encoder.text_token match, :attribute_value
              state = :attribute
            elsif match = scan(/["']/)
              if in_attribute == :script
                encoder.begin_group :inline
                encoder.text_token match, :inline_delimiter
                if scan(/javascript:[ \t]*/)
                  encoder.text_token matched, :comment
                end
                code = scan_until(match == '"' ? /(?="|\z)/ : /(?='|\z)/)
                scan_java_script encoder, code
                match = scan(/["']/)
                encoder.text_token match, :inline_delimiter if match
                encoder.end_group :inline
                state = :attribute
                in_attribute = nil
              else
                encoder.begin_group :string
                state = :attribute_value_string
                plain_string_content = PLAIN_STRING_CONTENT[match]
                encoder.text_token match, :delimiter
              end
            elsif match = scan(/#{TAG_END}/o)
              encoder.text_token match, :tag
              state = :initial
            else
              encoder.text_token getch, :error
            end
            
          when :attribute_value_string
            if match = scan(plain_string_content)
              encoder.text_token match, :content
            elsif match = scan(/['"]/)
              encoder.text_token match, :delimiter
              encoder.end_group :string
              state = :attribute
            elsif match = scan(/#{ENTITY}/ox)
              encoder.text_token match, :entity
            elsif match = scan(/&/)
              encoder.text_token match, :content
            elsif match = scan(/[\n>]/)
              encoder.end_group :string
              state = :initial
              encoder.text_token match, :error
            end
            
          when :in_special_tag
            case in_tag
            when 'script'
              encoder.text_token match, :space if match = scan(/[ \t]*\n/)
              if scan(/(\s*<!--)(?:(.*?)(-->)|(.*))/m)
                code = self[2] || self[4]
                closing = self[3]
                encoder.text_token self[1], :comment
              else
                code = scan_until(/(?=(?:\n\s*)?<\/script>)|\z/)
                closing = false
              end
              unless code.empty?
                encoder.begin_group :inline
                scan_java_script encoder, code
                encoder.end_group :inline
              end
              encoder.text_token closing, :comment if closing
              state = :initial
            else
              raise 'unknown special tag: %p' % [in_tag]
            end
            
          else
            raise_inspect 'Unknown state: %p' % [state], encoder
            
          end
          
        end
        
      end
      
      if options[:keep_state]
        @state = state
        @plain_string_content = plain_string_content
      end
      
      encoder.end_group :string if state == :attribute_value_string
      
      encoder
    end
    
  end
  
end
end
