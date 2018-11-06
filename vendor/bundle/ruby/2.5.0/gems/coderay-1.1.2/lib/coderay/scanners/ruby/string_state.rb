# encoding: utf-8
module CodeRay
module Scanners
  
  class Ruby
    
    class StringState < Struct.new :type, :interpreted, :delim, :heredoc,
      :opening_paren, :paren_depth, :pattern, :next_state  # :nodoc: all
      
      CLOSING_PAREN = Hash[ *%w[
        ( )
        [ ]
        < >
        { }
      ] ].each { |k,v| k.freeze; v.freeze }  # debug, if I try to change it with <<
      
      STRING_PATTERN = Hash.new do |h, k|
        delim, interpreted = *k
        delim_pattern = Regexp.escape(delim)
        if closing_paren = CLOSING_PAREN[delim]
          delim_pattern << Regexp.escape(closing_paren)
        end
        delim_pattern << '\\\\' unless delim == '\\'
        
        # special_escapes =
        #   case interpreted
        #   when :regexp_symbols
        #     '| [|?*+(){}\[\].^$]'
        #   end
        
        if interpreted && delim != '#'
          / (?= [#{delim_pattern}] | \# [{$@] ) /mx
        else
          / (?= [#{delim_pattern}] ) /mx
        end.tap do |pattern|
          h[k] = pattern if (delim.respond_to?(:ord) ? delim.ord : delim[0]) < 256
        end
      end
      
      def self.simple_key_pattern delim
        if delim == "'"
          / (?> (?: [^\\']+ | \\. )* ) ' : /mx
        else
          / (?> (?: [^\\"\#]+ | \\. | \#\$[\\"] | \#\{[^\{\}]+\} | \#(?!\{) )* ) " : /mx
        end
      end
      
      def initialize kind, interpreted, delim, heredoc = false
        if heredoc
          pattern = heredoc_pattern delim, interpreted, heredoc == :indented
          delim = nil
        else
          pattern = STRING_PATTERN[ [delim, interpreted] ]
          if closing_paren = CLOSING_PAREN[delim]
            opening_paren = delim
            delim = closing_paren
            paren_depth = 1
          end
        end
        super kind, interpreted, delim, heredoc, opening_paren, paren_depth, pattern, :initial
      end
      
      def heredoc_pattern delim, interpreted, indented
        # delim = delim.dup  # workaround for old Ruby
        delim_pattern = Regexp.escape(delim)
        delim_pattern = / (?:\A|\n) #{ '(?>[ \t]*)' if indented } #{ Regexp.new delim_pattern } $ /x
        if interpreted
          / (?= #{delim_pattern}() | \\ | \# [{$@] ) /mx  # $1 set == end of heredoc
        else
          / (?= #{delim_pattern}() | \\ ) /mx
        end
      end
      
    end
    
  end
  
end
end
