##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/engine'
require 'erubis/enhancer'


module Erubis


  module CGenerator
    include Generator

    def self.supported_properties()  # :nodoc:
      return [
              [:indent, '',       "indent spaces (ex. '  ')"],
              [:out,    'stdout', "output file pointer name"],
            ]
    end

    def init_generator(properties={})
      super
      @escapefunc ||= "escape"
      @indent = properties[:indent] || ''
      @out = properties[:out] || 'stdout'
    end

    def add_preamble(src)
      src << "#line 1 \"#{self.filename}\"\n" if self.filename
    end

    def escape_text(text)
      @@table_ ||= { "\r"=>"\\r", "\n"=>"\\n", "\t"=>"\\t", '"'=>'\\"', "\\"=>"\\\\" }
      text.gsub!(/[\r\n\t"\\]/) { |m| @@table_[m] }
      return text
    end

    def escaped_expr(code)
      return "#{@escapefunc}(#{code.strip}, #{@out})"
    end

    def add_text(src, text)
      return if text.empty?
      src << (src.empty? || src[-1] == ?\n ? @indent : ' ')
      src << "fputs("
      i = 0
      text.each_line do |line|
        src << "\n" << @indent << '      ' if i > 0
        i += 1
        src << '"' << escape_text(line) << '"'
      end
      src << ", #{@out});"   #<< (text[-1] == ?\n ? "\n" : "")
      src << "\n" if text[-1] == ?\n
    end

    def add_stmt(src, code)
      src << code
    end

    def add_expr_literal(src, code)
      src << @indent if src.empty? || src[-1] == ?\n
      src << " fprintf(#{@out}, " << code.strip << ');'
    end

    def add_expr_escaped(src, code)
      src << @indent if src.empty? || src[-1] == ?\n
      src << ' ' << escaped_expr(code) << ';'
    end

    def add_expr_debug(src, code)
      code.strip!
      s = nil
      if code =~ /\A\".*?\"\s*,\s*(.*)/
        s = $1.gsub(/[%"]/, '\\\1') + '='
      end
      src << @indent if src.empty? || src[-1] == ?\n
      src << " fprintf(stderr, \"*** debug: #{s}\" #{code});"
    end

    def add_postamble(src)
      # empty
    end

  end


  ##
  ## engine for C
  ##
  class Ec < Basic::Engine
    include CGenerator
  end


  class EscapedEc < Ec
    include EscapeEnhancer
  end


  #class XmlEc < Ec
  #  include EscapeEnhancer
  #end

  class PI::Ec < PI::Engine
    include CGenerator

    def init_converter(properties={})
      @pi = 'c'
      super(properties)
    end

  end


end
