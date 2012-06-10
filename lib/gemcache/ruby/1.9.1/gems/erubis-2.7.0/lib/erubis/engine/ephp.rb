##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/engine'
require 'erubis/enhancer'


module Erubis


  module PhpGenerator
    include Generator

    def self.supported_properties()  # :nodoc:
      return []
    end

    def init_generator(properties={})
      super
      @escapefunc ||= 'htmlspecialchars'
    end

    def add_preamble(src)
      # empty
    end

    def escape_text(text)
      return text.gsub!(/<\?xml\b/, '<<?php ?>?xml') || text
    end

    def add_text(src, text)
      src << escape_text(text)
    end

    def add_expr_literal(src, code)
      code.strip!
      src << "<?php echo #{code}; ?>"
    end

    def add_expr_escaped(src, code)
      add_expr_literal(src, escaped_expr(code))
    end

    def add_expr_debug(src, code)
      code.strip!
      s = code.gsub(/\'/, "\\'")
      src << "<?php error_log('*** debug: #{s}='.(#{code}), 0); ?>"
    end

    def add_stmt(src, code)
      src << "<?php"
      src << " " if code[0] != ?\ #
      if code[-1] == ?\n
        code.chomp!
        src << code << "?>\n"
      else
        src << code << "?>"
      end
    end

    def add_postamble(src)
      # empty
    end

  end


  ##
  ## engine for PHP
  ##
  class Ephp < Basic::Engine
    include PhpGenerator
  end


  class EscapedEphp < Ephp
    include EscapeEnhancer
  end


  #class XmlEphp < Ephp
  #  include EscapeEnhancer
  #end


  class PI::Ephp < PI::Engine
    include PhpGenerator

    def init_converter(properties={})
      @pi = 'php'
      super(properties)
    end

  end


end
