##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/engine'
require 'erubis/enhancer'


module Erubis


  module CppGenerator
    include Generator

    def self.supported_properties()  # :nodoc:
      return [
              [:indent, '',       "indent spaces (ex. '  ')"],
              [:bufvar, '_buf',   "buffer variable name"],
            ]
    end

    def init_generator(properties={})
      super
      @escapefunc ||= "escape"
      @indent = properties[:indent] || ''
      @bufvar = properties[:bufvar] || '_buf'
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
      return "#{@escapefunc}(#{code.strip})"
    end

    def add_text(src, text)
      return if text.empty?
      src << (src.empty? || src[-1] == ?\n ? @indent : ' ')
      src << "_buf << "
      i = 0
      text.each_line do |line|
        src << "\n" << @indent << "        " if i > 0
        i += 1
        src << '"' << escape_text(line) << '"'
      end
      src << ";"   #<< (text[-1] == ?\n ? "\n" : "")
      src << "\n" if text[-1] == ?\n
    end

    def add_stmt(src, code)
      src << code
    end

    def add_expr_literal(src, code)
      src << @indent if src.empty? || src[-1] == ?\n
      src << " _buf << (" << code.strip << ");"
    end

    def add_expr_escaped(src, code)
      src << @indent if src.empty? || src[-1] == ?\n
      src << ' ' << escaped_expr(code) << ';'
    end

    def add_expr_debug(src, code)
      code.strip!
      src << @indent if src.empty? || src[-1] == ?\n
      src << " std::cerr << \"*** debug: #{code.gsub(/(")/, '\\\&')}=\" << (#{code});"
    end

    def add_postamble(src)
      # empty
    end

  end


  ##
  ## engine for C
  ##
  class Ecpp < Basic::Engine
    include CppGenerator
  end


  class EscapedEcpp < Ecpp
    include EscapeEnhancer
  end


  #class XmlEcpp < Ecpp
  #  include EscapeEnhancer
  #end

  class PI::Ecpp < PI::Engine
    include CppGenerator

    def init_converter(properties={})
      @pi = 'cpp'
      super(properties)
    end

  end


end
