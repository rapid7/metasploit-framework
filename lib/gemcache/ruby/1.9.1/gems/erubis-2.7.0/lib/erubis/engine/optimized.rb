##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##


require 'erubis/engine/eruby'


module Erubis


  module OptimizedGenerator
    include Generator

    def self.supported_properties()  # :nodoc:
      return []
    end

    def init_generator(properties={})
      super
      @escapefunc ||= "Erubis::XmlHelper.escape_xml"
      @initialized = false
      @prev_is_expr = false
    end

    protected

    def escape_text(text)
      text.gsub(/['\\]/, '\\\\\&')   # "'" => "\\'",  '\\' => '\\\\'
    end

    def escaped_expr(code)
      @escapefunc ||= 'Erubis::XmlHelper.escape_xml'
      return "#{@escapefunc}(#{code})"
    end

    def switch_to_expr(src)
      return if @prev_is_expr
      @prev_is_expr = true
      src << ' _buf'
    end

    def switch_to_stmt(src)
      return unless @prev_is_expr
      @prev_is_expr = false
      src << ';'
    end

    def add_preamble(src)
      #@initialized = false
      #@prev_is_expr = false
    end

    def add_text(src, text)
      return if text.empty?
      if @initialized
        switch_to_expr(src)
        src << " << '" << escape_text(text) << "'"
      else
        src << "_buf = '" << escape_text(text) << "';"
        @initialized = true
      end
    end

    def add_stmt(src, code)
      switch_to_stmt(src) if @initialized
      #super
      src << code
      src << ';' unless code[-1] == ?\n
    end

    def add_expr_literal(src, code)
      unless @initialized; src << "_buf = ''"; @initialized = true; end
      switch_to_expr(src)
      src << " << (" << code << ").to_s"
    end

    def add_expr_escaped(src, code)
      unless @initialized; src << "_buf = ''"; @initialized = true; end
      switch_to_expr(src)
      src << " << " << escaped_expr(code)
    end

    def add_expr_debug(src, code)
      code.strip!
      s = (code.dump =~ /\A"(.*)"\z/) && $1
      src << ' $stderr.puts("*** debug: ' << s << '=#{(' << code << ').inspect}");'
    end

    def add_postamble(src)
      #super if @initialized
      src << "\n_buf\n" if @initialized
    end

  end  # end of class OptimizedEruby


  ##
  ## Eruby class which generates optimized ruby code
  ##
  class OptimizedEruby < Basic::Engine    # Eruby
    include RubyEvaluator
    include OptimizedGenerator

    def init_converter(properties={})
      @pi = 'rb'
      super(properties)
    end

  end


  ##
  ## XmlEruby class which generates optimized ruby code
  ##
  class OptimizedXmlEruby < OptimizedEruby
    include EscapeEnhancer

    def add_expr_debug(src, code)
      switch_to_stmt(src) if indicator == '===' && !@initialized
      super
    end

  end  # end of class OptimizedXmlEruby

end
