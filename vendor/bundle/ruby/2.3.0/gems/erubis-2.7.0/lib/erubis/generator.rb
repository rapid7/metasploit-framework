##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

require 'erubis/util'

module Erubis


  ##
  ## code generator, called by Converter module
  ##
  module Generator

    def self.supported_properties()  # :nodoc:
      return [
              [:escapefunc,    nil,    "escape function name"],
            ]
    end

    attr_accessor :escapefunc

    def init_generator(properties={})
      @escapefunc = properties[:escapefunc]
    end


    ## (abstract) escape text string
    ##
    ## ex.
    ##   def escape_text(text)
    ##     return text.dump
    ##     # or return "'" + text.gsub(/['\\]/, '\\\\\&') + "'"
    ##   end
    def escape_text(text)
      not_implemented
    end

    ## return escaped expression code (ex. 'h(...)' or 'htmlspecialchars(...)')
    def escaped_expr(code)
      code.strip!
      return "#{@escapefunc}(#{code})"
    end

    ## (abstract) add @preamble to src
    def add_preamble(src)
      not_implemented
    end

    ## (abstract) add text string to src
    def add_text(src, text)
      not_implemented
    end

    ## (abstract) add statement code to src
    def add_stmt(src, code)
      not_implemented
    end

    ## (abstract) add expression literal code to src. this is called by add_expr().
    def add_expr_literal(src, code)
      not_implemented
    end

    ## (abstract) add escaped expression code to src. this is called by add_expr().
    def add_expr_escaped(src, code)
      not_implemented
    end

    ## (abstract) add expression code to src for debug. this is called by add_expr().
    def add_expr_debug(src, code)
      not_implemented
    end

    ## (abstract) add @postamble to src
    def add_postamble(src)
      not_implemented
    end


  end


end
