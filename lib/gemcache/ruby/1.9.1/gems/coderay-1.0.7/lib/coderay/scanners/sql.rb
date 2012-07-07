module CodeRay module Scanners
  
  # by Josh Goebel
  class SQL < Scanner

    register_for :sql
    
    KEYWORDS = %w(
      all and any as before begin between by case check collate
      each else end exists
      for foreign from full group having if in inner is join
      like not of on or order outer over references
      then to union using values when where
      left right distinct
    )
    
    OBJECTS = %w(
      database databases table tables column columns fields index constraint
      constraints transaction function procedure row key view trigger
    )
    
    COMMANDS = %w(
      add alter comment create delete drop grant insert into select update set
      show prompt begin commit rollback replace truncate
    )
    
    PREDEFINED_TYPES = %w(
      char varchar varchar2 enum binary text tinytext mediumtext
      longtext blob tinyblob mediumblob longblob timestamp
      date time datetime year double decimal float int
      integer tinyint mediumint bigint smallint unsigned bit
      bool boolean hex bin oct
    )
    
    PREDEFINED_FUNCTIONS = %w( sum cast substring abs pi count min max avg now )
    
    DIRECTIVES = %w( 
      auto_increment unique default charset initially deferred
      deferrable cascade immediate read write asc desc after
      primary foreign return engine
    )
    
    PREDEFINED_CONSTANTS = %w( null true false )
    
    IDENT_KIND = WordList::CaseIgnoring.new(:ident).
      add(KEYWORDS, :keyword).
      add(OBJECTS, :type).
      add(COMMANDS, :class).
      add(PREDEFINED_TYPES, :predefined_type).
      add(PREDEFINED_CONSTANTS, :predefined_constant).
      add(PREDEFINED_FUNCTIONS, :predefined).
      add(DIRECTIVES, :directive)
    
    ESCAPE = / [rbfntv\n\\\/'"] | x[a-fA-F0-9]{1,2} | [0-7]{1,3} | . /mx
    UNICODE_ESCAPE =  / u[a-fA-F0-9]{4} | U[a-fA-F0-9]{8} /x
    
    STRING_PREFIXES = /[xnb]|_\w+/i
    
    def scan_tokens encoder, options
      
      state = :initial
      string_type = nil
      string_content = ''
      name_expected = false
      
      until eos?
        
        if state == :initial
          
          if match = scan(/ \s+ | \\\n /x)
            encoder.text_token match, :space
          
          elsif match = scan(/(?:--\s?|#).*/)
            encoder.text_token match, :comment
            
          elsif match = scan(%r( /\* (!)? (?: .*? \*/ | .* ) )mx)
            encoder.text_token match, self[1] ? :directive : :comment
            
          elsif match = scan(/ [*\/=<>:;,!&^|()\[\]{}~%] | [-+\.](?!\d) /x)
            name_expected = true if match == '.' && check(/[A-Za-z_]/)
            encoder.text_token match, :operator
            
          elsif match = scan(/(#{STRING_PREFIXES})?([`"'])/o)
            prefix = self[1]
            string_type = self[2]
            encoder.begin_group :string
            encoder.text_token prefix, :modifier if prefix
            match = string_type
            state = :string
            encoder.text_token match, :delimiter
            
          elsif match = scan(/ @? [A-Za-z_][A-Za-z_0-9]* /x)
            encoder.text_token match, name_expected ? :ident : (match[0] == ?@ ? :variable : IDENT_KIND[match])
            name_expected = false
            
          elsif match = scan(/0[xX][0-9A-Fa-f]+/)
            encoder.text_token match, :hex
            
          elsif match = scan(/0[0-7]+(?![89.eEfF])/)
            encoder.text_token match, :octal
            
          elsif match = scan(/[-+]?(?>\d+)(?![.eEfF])/)
            encoder.text_token match, :integer
            
          elsif match = scan(/[-+]?(?:\d[fF]|\d*\.\d+(?:[eE][+-]?\d+)?|\d+[eE][+-]?\d+)/)
            encoder.text_token match, :float
          
          elsif match = scan(/\\N/)
            encoder.text_token match, :predefined_constant
            
          else
            encoder.text_token getch, :error
            
          end
          
        elsif state == :string
          if match = scan(/[^\\"'`]+/)
            string_content << match
            next
          elsif match = scan(/["'`]/)
            if string_type == match
              if peek(1) == string_type  # doubling means escape
                string_content << string_type << getch
                next
              end
              unless string_content.empty?
                encoder.text_token string_content, :content
                string_content = ''
              end
              encoder.text_token match, :delimiter
              encoder.end_group :string
              state = :initial
              string_type = nil
            else
              string_content << match
            end
          elsif match = scan(/ \\ (?: #{ESCAPE} | #{UNICODE_ESCAPE} ) /mox)
            unless string_content.empty?
              encoder.text_token string_content, :content
              string_content = ''
            end
            encoder.text_token match, :char
          elsif match = scan(/ \\ . /mox)
            string_content << match
            next
          elsif match = scan(/ \\ | $ /x)
            unless string_content.empty?
              encoder.text_token string_content, :content
              string_content = ''
            end
            encoder.text_token match, :error
            state = :initial
          else
            raise "else case \" reached; %p not handled." % peek(1), encoder
          end
          
        else
          raise 'else-case reached', encoder
          
        end
        
      end
      
      if state == :string
        encoder.end_group state
      end
      
      encoder
      
    end
    
  end
  
end end