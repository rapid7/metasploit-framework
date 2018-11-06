module CodeRay
module Scanners
  
  load :ruby
  load :html
  load :java_script
  
  class HAML < Scanner
    
    register_for :haml
    title 'HAML Template'
    
    KINDS_NOT_LOC = HTML::KINDS_NOT_LOC
    
  protected
    
    def setup
      super
      @ruby_scanner          = CodeRay.scanner :ruby, :tokens => @tokens, :keep_tokens => true
      @embedded_ruby_scanner = CodeRay.scanner :ruby, :tokens => @tokens, :keep_tokens => true, :state => @ruby_scanner.interpreted_string_state
      @html_scanner          = CodeRay.scanner :html, :tokens => @tokens, :keep_tokens => true
    end
    
    def scan_tokens encoder, options
      
      match = nil
      code = ''
      
      until eos?
        
        if bol?
          if match = scan(/!!!.*/)
            encoder.text_token match, :doctype
            next
          end
          
          if match = scan(/(?>( *)(\/(?!\[if)|-\#|:javascript|:ruby|:\w+) *)(?=\n)/)
            encoder.text_token match, :comment
            
            code = self[2]
            if match = scan(/(?:\n+#{self[1]} .*)+/)
              case code
              when '/', '-#'
                encoder.text_token match, :comment
              when ':javascript'
                # TODO: recognize #{...} snippets inside JavaScript
                @java_script_scanner ||= CodeRay.scanner :java_script, :tokens => @tokens, :keep_tokens => true
                @java_script_scanner.tokenize match, :tokens => encoder
              when ':ruby'
                @ruby_scanner.tokenize match, :tokens => encoder
              when /:\w+/
                encoder.text_token match, :comment
              else
                raise 'else-case reached: %p' % [code]
              end
            end
          end
          
          if match = scan(/ +/)
            encoder.text_token match, :space
          end
          
          if match = scan(/\/.*/)
            encoder.text_token match, :comment
            next
          end
          
          if match = scan(/\\/)
            encoder.text_token match, :plain
            if match = scan(/.+/)
              @html_scanner.tokenize match, :tokens => encoder
            end
            next
          end
          
          tag = false
          
          if match = scan(/%[-\w:]+\/?/)
            encoder.text_token match, :tag
            # if match = scan(/( +)(.+)/)
            #   encoder.text_token self[1], :space
            #   @embedded_ruby_scanner.tokenize self[2], :tokens => encoder
            # end
            tag = true
          end
          
          while match = scan(/([.#])[-\w]*\w/)
            encoder.text_token match, self[1] == '#' ? :constant : :class
            tag = true
          end
          
          if tag && match = scan(/(\()([^)]+)?(\))?/)
            # TODO: recognize title=@title, class="widget_#{@widget.number}"
            encoder.text_token self[1], :plain
            @html_scanner.tokenize self[2], :tokens => encoder, :state => :attribute if self[2]
            encoder.text_token self[3], :plain if self[3]
          end
          
          if tag && match = scan(/\{/)
            encoder.text_token match, :plain
            
            code = ''
            level = 1
            while true
              code << scan(/([^\{\},\n]|, *\n?)*/)
              case match = getch
              when '{'
                level += 1
                code << match
              when '}'
                level -= 1
                if level > 0
                  code << match
                else
                  break
                end
              when "\n", ",", nil
                break
              end
            end
            @ruby_scanner.tokenize code, :tokens => encoder unless code.empty?
            
            encoder.text_token match, :plain if match
          end
          
          if tag && match = scan(/(\[)([^\]\n]+)?(\])?/)
            encoder.text_token self[1], :plain
            @ruby_scanner.tokenize self[2], :tokens => encoder if self[2]
            encoder.text_token self[3], :plain if self[3]
          end
          
          if tag && match = scan(/\//)
            encoder.text_token match, :tag
          end
          
          if scan(/(>?<?[-=]|[&!]=|(& |!)|~)( *)([^,\n\|]+(?:(, *|\|(?=.|\n.*\|$))\n?[^,\n\|]*)*)?/)
            encoder.text_token self[1] + self[3], :plain
            if self[4]
              if self[2]
                @embedded_ruby_scanner.tokenize self[4], :tokens => encoder
              else
                @ruby_scanner.tokenize self[4], :tokens => encoder
              end
            end
          elsif match = scan(/((?:<|><?)(?![!?\/\w]))?(.+)?/)
            encoder.text_token self[1], :plain if self[1]
            # TODO: recognize #{...} snippets
            @html_scanner.tokenize self[2], :tokens => encoder if self[2]
          end
          
        elsif match = scan(/.+/)
          @html_scanner.tokenize match, :tokens => encoder
          
        end
        
        if match = scan(/\n/)
          encoder.text_token match, :space
        end
      end
      
      encoder
      
    end
    
  end
  
end
end
