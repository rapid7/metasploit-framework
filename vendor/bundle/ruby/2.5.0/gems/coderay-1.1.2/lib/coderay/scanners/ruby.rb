module CodeRay
module Scanners
  
  # This scanner is really complex, since Ruby _is_ a complex language!
  #
  # It tries to highlight 100% of all common code,
  # and 90% of strange codes.
  #
  # It is optimized for HTML highlighting, and is not very useful for
  # parsing or pretty printing.
  class Ruby < Scanner
    
    register_for :ruby
    file_extension 'rb'
    
    autoload :Patterns,    CodeRay.coderay_path('scanners', 'ruby', 'patterns')
    autoload :StringState, CodeRay.coderay_path('scanners', 'ruby', 'string_state')
    
    def interpreted_string_state
      StringState.new :string, true, '"'
    end
    
  protected
    
    def setup
      @state = :initial
    end
    
    def scan_tokens encoder, options
      state, heredocs = options[:state] || @state
      heredocs = heredocs.dup if heredocs.is_a?(Array)
      
      if state && state.instance_of?(StringState)
        encoder.begin_group state.type
      end
      
      last_state = nil
      
      method_call_expected = false
      value_expected = true
      
      inline_block_stack = nil
      inline_block_curly_depth = 0
      
      if heredocs
        state = heredocs.shift
        encoder.begin_group state.type
        heredocs = nil if heredocs.empty?
      end
      
      # def_object_stack = nil
      # def_object_paren_depth = 0
      
      patterns = Patterns  # avoid constant lookup
      
      unicode = string.respond_to?(:encoding) && string.encoding.name == 'UTF-8'
      
      until eos?
        
        if state.instance_of? ::Symbol
          
          if match = scan(/[ \t\f\v]+/)
            encoder.text_token match, :space
            
          elsif match = scan(/\n/)
            if heredocs
              unscan  # heredoc scanning needs \n at start
              state = heredocs.shift
              encoder.begin_group state.type
              heredocs = nil if heredocs.empty?
            else
              state = :initial if state == :undef_comma_expected
              encoder.text_token match, :space
              value_expected = true
            end
            
          elsif match = scan(bol? ? / \#(!)?.* | #{patterns::RUBYDOC_OR_DATA} /ox : /\#.*/)
            encoder.text_token match, self[1] ? :doctype : :comment
            
          elsif match = scan(/\\\n/)
            if heredocs
              unscan  # heredoc scanning needs \n at start
              encoder.text_token scan(/\\/), :space
              state = heredocs.shift
              encoder.begin_group state.type
              heredocs = nil if heredocs.empty?
            else
              encoder.text_token match, :space
            end
            
          elsif state == :initial
            
            # IDENTS #
            if !method_call_expected &&
               match = scan(unicode ? /#{patterns::METHOD_NAME}/uo :
                                      /#{patterns::METHOD_NAME}/o)
              
              kind = patterns::IDENT_KIND[match]
              if value_expected != :colon_expected && scan(/:(?!:)/)
                value_expected = true
                encoder.text_token match, :key
                encoder.text_token ':',   :operator
              else
                value_expected = false
                if kind == :ident
                  if match[/\A[A-Z]/] && !(match[/[!?]$/] || match?(/\(/))
                    kind = :constant
                  end
                elsif kind == :keyword
                  state = patterns::KEYWORD_NEW_STATE[match]
                  if patterns::KEYWORDS_EXPECTING_VALUE[match]
                    value_expected = match == 'when' ? :colon_expected : true
                  end
                end
                value_expected = true if !value_expected && check(/#{patterns::VALUE_FOLLOWS}/o)
                encoder.text_token match, kind
              end
              
            elsif method_call_expected &&
               match = scan(unicode ? /#{patterns::METHOD_AFTER_DOT}/uo :
                                      /#{patterns::METHOD_AFTER_DOT}/o)
              if method_call_expected == '::' && match[/\A[A-Z]/] && !match?(/\(/)
                encoder.text_token match, :constant
              else
                encoder.text_token match, :ident
              end
              method_call_expected = false
              value_expected = check(/#{patterns::VALUE_FOLLOWS}/o)
              
            # OPERATORS #
            elsif !method_call_expected && match = scan(/ (\.(?!\.)|::) | ( \.\.\.? | ==?=? | [,\(\[\{] ) | [\)\]\}] /x)
              method_call_expected = self[1]
              value_expected = !method_call_expected && !!self[2]
              if inline_block_stack
                case match
                when '{'
                  inline_block_curly_depth += 1
                when '}'
                  inline_block_curly_depth -= 1
                  if inline_block_curly_depth == 0  # closing brace of inline block reached
                    state, inline_block_curly_depth, heredocs = inline_block_stack.pop
                    inline_block_stack = nil if inline_block_stack.empty?
                    heredocs = nil if heredocs && heredocs.empty?
                    encoder.text_token match, :inline_delimiter
                    encoder.end_group :inline
                    next
                  end
                end
              end
              encoder.text_token match, :operator
              
            elsif match = scan(unicode ? /#{patterns::SYMBOL}/uo :
                                         /#{patterns::SYMBOL}/o)
              case delim = match[1]
              when ?', ?"
                encoder.begin_group :symbol
                encoder.text_token ':', :symbol
                match = delim.chr
                encoder.text_token match, :delimiter
                state = self.class::StringState.new :symbol, delim == ?", match
              else
                encoder.text_token match, :symbol
                value_expected = false
              end
              
            elsif match = scan(/ ' (?:(?>[^'\\]*) ')? | " (?:(?>[^"\\\#]*) ")? /mx)
              if match.size == 1
                kind = check(self.class::StringState.simple_key_pattern(match)) ? :key : :string
                encoder.begin_group kind
                encoder.text_token match, :delimiter
                state = self.class::StringState.new kind, match == '"', match  # important for streaming
              else
                kind = value_expected == true && scan(/:/) ? :key : :string
                encoder.begin_group kind
                encoder.text_token match[0,1], :delimiter
                encoder.text_token match[1..-2], :content if match.size > 2
                encoder.text_token match[-1,1], :delimiter
                encoder.end_group kind
                encoder.text_token ':', :operator if kind == :key
                value_expected = false
              end
              
            elsif match = scan(unicode ? /#{patterns::INSTANCE_VARIABLE}/uo :
                                         /#{patterns::INSTANCE_VARIABLE}/o)
              value_expected = false
              encoder.text_token match, :instance_variable
              
            elsif value_expected && match = scan(/\//)
              encoder.begin_group :regexp
              encoder.text_token match, :delimiter
              state = self.class::StringState.new :regexp, true, '/'
              
            elsif match = scan(value_expected ? /[-+]?#{patterns::NUMERIC}/o : /#{patterns::NUMERIC}/o)
              if method_call_expected
                encoder.text_token match, :error
                method_call_expected = false
              else
                kind = self[1] ? :float : :integer  # TODO: send :hex/:octal/:binary
                match << 'r' if match !~ /e/i && scan(/r/)
                match << 'i' if scan(/i/)
                encoder.text_token match, kind
              end
              value_expected = false
              
            elsif match = scan(/ [-+!~^\/]=? | [:;] | &\. | [*|&]{1,2}=? | >>? /x)
              value_expected = true
              encoder.text_token match, :operator
              
            elsif value_expected && match = scan(/#{patterns::HEREDOC_OPEN}/o)
              quote = self[3]
              delim = self[quote ? 4 : 2]
              kind = patterns::QUOTE_TO_TYPE[quote]
              encoder.begin_group kind
              encoder.text_token match, :delimiter
              encoder.end_group kind
              heredocs ||= []  # create heredocs if empty
              heredocs << self.class::StringState.new(kind, quote != "'", delim,
                self[1] ? :indented : :linestart)
              value_expected = false
              
            elsif value_expected && match = scan(/#{patterns::FANCY_STRING_START}/o)
              kind = patterns::FANCY_STRING_KIND[self[1]]
              encoder.begin_group kind
              state = self.class::StringState.new kind, patterns::FANCY_STRING_INTERPRETED[self[1]], self[2]
              encoder.text_token match, :delimiter
              
            elsif value_expected && match = scan(/#{patterns::CHARACTER}/o)
              value_expected = false
              encoder.text_token match, :integer
              
            elsif match = scan(/ %=? | <(?:<|=>?)? | \? /x)
              value_expected = match == '?' ? :colon_expected : true
              encoder.text_token match, :operator
              
            elsif match = scan(/`/)
              encoder.begin_group :shell
              encoder.text_token match, :delimiter
              state = self.class::StringState.new :shell, true, match
              
            elsif match = scan(unicode ? /#{patterns::GLOBAL_VARIABLE}/uo :
                                         /#{patterns::GLOBAL_VARIABLE}/o)
              encoder.text_token match, :global_variable
              value_expected = false
              
            elsif match = scan(unicode ? /#{patterns::CLASS_VARIABLE}/uo :
                                         /#{patterns::CLASS_VARIABLE}/o)
              encoder.text_token match, :class_variable
              value_expected = false
              
            elsif match = scan(/\\\z/)
              encoder.text_token match, :space
              
            else
              if method_call_expected
                method_call_expected = false
                next
              end
              unless unicode
                # check for unicode
                $DEBUG_BEFORE, $DEBUG = $DEBUG, false
                begin
                  if check(/./mu).size > 1
                    # seems like we should try again with unicode
                    unicode = true
                  end
                rescue
                  # bad unicode char; use getch
                ensure
                  $DEBUG = $DEBUG_BEFORE
                end
                next if unicode
              end
              
              encoder.text_token getch, :error
              
            end
            
            if last_state
              state = last_state unless state.is_a?(StringState)  # otherwise, a simple 'def"' results in unclosed tokens
              last_state = nil
            end
            
          elsif state == :def_expected
            if match = scan(unicode ? /(?>#{patterns::METHOD_NAME_EX})(?!\.|::)/uo :
                                      /(?>#{patterns::METHOD_NAME_EX})(?!\.|::)/o)
              encoder.text_token match, :method
              state = :initial
            else
              last_state = :dot_expected
              state = :initial
            end
            
          elsif state == :dot_expected
            if match = scan(/\.|::/)
              # invalid definition
              state = :def_expected
              encoder.text_token match, :operator
            else
              state = :initial
            end
            
          elsif state == :module_expected
            if match = scan(/<</)
              encoder.text_token match, :operator
            else
              state = :initial
              if match = scan(unicode ? / (?:#{patterns::IDENT}::)* #{patterns::IDENT} /oux :
                                        / (?:#{patterns::IDENT}::)* #{patterns::IDENT} /ox)
                encoder.text_token match, :class
              end
            end
            
          elsif state == :undef_expected
            state = :undef_comma_expected
            if match = scan(unicode ? /(?>#{patterns::METHOD_NAME_EX})(?!\.|::)/uo :
                                      /(?>#{patterns::METHOD_NAME_EX})(?!\.|::)/o)
              encoder.text_token match, :method
            elsif match = scan(/#{patterns::SYMBOL}/o)
              case delim = match[1]
              when ?', ?"
                encoder.begin_group :symbol
                encoder.text_token ':', :symbol
                match = delim.chr
                encoder.text_token match, :delimiter
                state = self.class::StringState.new :symbol, delim == ?", match
                state.next_state = :undef_comma_expected
              else
                encoder.text_token match, :symbol
              end
            else
              state = :initial
            end
            
          elsif state == :undef_comma_expected
            if match = scan(/,/)
              encoder.text_token match, :operator
              state = :undef_expected
            else
              state = :initial
            end
            
          elsif state == :alias_expected
            match = scan(unicode ? /(#{patterns::METHOD_NAME_OR_SYMBOL})([ \t]+)(#{patterns::METHOD_NAME_OR_SYMBOL})/uo :
                                   /(#{patterns::METHOD_NAME_OR_SYMBOL})([ \t]+)(#{patterns::METHOD_NAME_OR_SYMBOL})/o)
            
            if match
              encoder.text_token self[1], (self[1][0] == ?: ? :symbol : :method)
              encoder.text_token self[2], :space
              encoder.text_token self[3], (self[3][0] == ?: ? :symbol : :method)
            end
            state = :initial
            
          else
            #:nocov:
            raise_inspect 'Unknown state: %p' % [state], encoder
            #:nocov:
          end
          
        else  # StringState
          
          match = scan_until(state.pattern) || scan_rest
          unless match.empty?
            encoder.text_token match, :content
            break if eos?
          end
          
          if state.heredoc && self[1]  # end of heredoc
            match = getch
            match << scan_until(/$/) unless eos?
            encoder.text_token match, :delimiter unless match.empty?
            encoder.end_group state.type
            state = state.next_state
            next
          end
          
          case match = getch
          
          when state.delim
            if state.paren_depth
              state.paren_depth -= 1
              if state.paren_depth > 0
                encoder.text_token match, :content
                next
              end
            end
            encoder.text_token match, :delimiter
            if state.type == :regexp && !eos?
              match = scan(/#{patterns::REGEXP_MODIFIERS}/o)
              encoder.text_token match, :modifier unless match.empty?
            end
            encoder.end_group state.type
            value_expected = false
            state = state.next_state
            
          when '\\'
            if state.interpreted
              if esc = scan(/#{patterns::ESCAPE}/o)
                encoder.text_token match + esc, :char
              else
                encoder.text_token match, :error
              end
            else
              case esc = getch
              when nil
                encoder.text_token match, :content
              when state.delim, '\\'
                encoder.text_token match + esc, :char
              else
                encoder.text_token match + esc, :content
              end
            end
            
          when '#'
            case peek(1)
            when '{'
              inline_block_stack ||= []
              inline_block_stack << [state, inline_block_curly_depth, heredocs]
              value_expected = true
              state = :initial
              inline_block_curly_depth = 1
              encoder.begin_group :inline
              encoder.text_token match + getch, :inline_delimiter
            when '$', '@'
              encoder.text_token match, :escape
              last_state = state
              state = :initial
            else
              #:nocov:
              raise_inspect 'else-case # reached; #%p not handled' % [peek(1)], encoder
              #:nocov:
            end
            
          when state.opening_paren
            state.paren_depth += 1
            encoder.text_token match, :content
            
          else
            #:nocov
            raise_inspect 'else-case " reached; %p not handled, state = %p' % [match, state], encoder
            #:nocov:
            
          end
          
        end
        
      end
      
      # cleaning up
      if state.is_a? StringState
        encoder.end_group state.type
      end
      
      if options[:keep_state]
        if state.is_a?(StringState) && state.heredoc
          (heredocs ||= []).unshift state
          state = :initial
        elsif heredocs && heredocs.empty?
          heredocs = nil
        end
        @state = state, heredocs
      end
      
      if inline_block_stack
        until inline_block_stack.empty?
          state, = *inline_block_stack.pop
          encoder.end_group :inline
          encoder.end_group state.type
        end
      end
      
      encoder
    end
    
  end
  
end
end
