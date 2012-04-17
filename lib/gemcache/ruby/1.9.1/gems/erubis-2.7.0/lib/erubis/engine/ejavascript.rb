##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/engine'
require 'erubis/enhancer'


module Erubis


  module JavascriptGenerator
    include Generator

    def self.supported_properties()   # :nodoc:
      list = []
      #list << [:indent,   '',       "indent spaces (ex. '  ')"]
      #list << [:bufvar,      '_buf',   "output buffer variable name"]
      list << [:docwrite, true,     "use 'document.write()' when true"]
      return list
    end

    def init_generator(properties={})
      super
      @escapefunc ||= 'escape'
      @indent = properties[:indent] || ''
      @bufvar = properties[:bufvar] || '_buf'
      @docwrite = properties[:docwrite] != false  # '!= false' will be removed in the next release
    end

    def add_preamble(src)
      src << "#{@indent}var #{@bufvar} = [];"
    end

    def escape_text(text)
      @@table_ ||= { "\r"=>"\\r", "\n"=>"\\n\\\n", "\t"=>"\\t", '"'=>'\\"', "\\"=>"\\\\" }
      return text.gsub!(/[\r\n\t"\\]/) { |m| @@table_[m] } || text
    end

    def add_indent(src, indent)
      src << (src.empty? || src[-1] == ?\n ? indent : ' ')
    end

    def add_text(src, text)
      return if text.empty?
      add_indent(src, @indent)
      src << @bufvar << '.push("'
      s = escape_text(text)
      if s[-1] == ?\n
        s[-2, 2] = ''
        src << s << "\");\n"
      else
        src << s << "\");"
      end
    end

    def add_stmt(src, code)
      src << code
    end

    def add_expr_literal(src, code)
      add_indent(src, @indent)
      code.strip!
      src << "#{@bufvar}.push(#{code});"
    end

    def add_expr_escaped(src, code)
      add_expr_literal(src, escaped_expr(code))
    end

    def add_expr_debug(src, code)
      add_indent(src, @indent)
      code.strip!
      src << "alert(\"*** debug: #{code}=\"+(#{code}));"
    end

    def add_postamble(src)
      src << "\n" if src[-1] == ?;
      if @docwrite
        src << @indent << 'document.write(' << @bufvar << ".join(\"\"));\n"
      else
        src << @indent << @bufvar << ".join(\"\");\n"
      end
    end

  end


  ##
  ## engine for JavaScript
  ##
  class Ejavascript < Basic::Engine
    include JavascriptGenerator
  end


  class EscapedEjavascript < Ejavascript
    include EscapeEnhancer
  end


  #class XmlEjavascript < Ejavascript
  #  include EscapeEnhancer
  #end


  class PI::Ejavascript < PI::Engine
    include JavascriptGenerator

    def init_converter(properties={})
      @pi = 'js'
      super(properties)
    end

  end


end
