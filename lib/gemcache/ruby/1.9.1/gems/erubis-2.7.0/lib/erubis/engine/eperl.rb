##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/engine'
require 'erubis/enhancer'


module Erubis


  module PerlGenerator
    include Generator

    def self.supported_properties()  # :nodoc:
      return [
              [:func, 'print', "function name"],
              ]
    end

    def init_generator(properties={})
      super
      @escapefunc ||= 'encode_entities'
      @func = properties[:func] || 'print'
    end

    def add_preamble(src)
      src << "use HTML::Entities; ";
    end

    def escape_text(text)
      return text.gsub!(/['\\]/, '\\\\\&') || text
    end

    def add_text(src, text)
      src << @func << "('" << escape_text(text) << "'); " unless text.empty?
    end

    def add_expr_literal(src, code)
      code.strip!
      src << @func << "(" << code << "); "
    end

    def add_expr_escaped(src, code)
      add_expr_literal(src, escaped_expr(code))
    end

    def add_expr_debug(src, code)
      code.strip!
      s = code.gsub(/\'/, "\\'")
      src << @func << "('*** debug: #{code}=', #{code}, \"\\n\");"
    end

    def add_stmt(src, code)
      src << code
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
    end

  end


  ##
  ## engine for Perl
  ##
  class Eperl < Basic::Engine
    include PerlGenerator
  end


  class EscapedEperl < Eperl
    include EscapeEnhancer
  end


  #class XmlEperl < Eperl
  #  include EscapeEnhancer
  #end


  class PI::Eperl < PI::Engine
    include PerlGenerator

    def init_converter(properties={})
      @pi = 'perl'
      super(properties)
    end

  end


end
