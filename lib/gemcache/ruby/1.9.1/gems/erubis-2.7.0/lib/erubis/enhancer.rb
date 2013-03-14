##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##


module Erubis


  ##
  ## switch '<%= ... %>' to escaped and '<%== ... %>' to unescaped
  ##
  ## ex.
  ##   class XmlEruby < Eruby
  ##     include EscapeEnhancer
  ##   end
  ##
  ## this is language-indenedent.
  ##
  module EscapeEnhancer

    def self.desc   # :nodoc:
      "switch '<%= %>' to escaped and '<%== %>' to unescaped"
    end

    #--
    #def self.included(klass)
    #  klass.class_eval <<-END
    #    alias _add_expr_literal add_expr_literal
    #    alias _add_expr_escaped add_expr_escaped
    #    alias add_expr_literal _add_expr_escaped
    #    alias add_expr_escaped _add_expr_literal
    #  END
    #end
    #++

    def add_expr(src, code, indicator)
      case indicator
      when '='
        @escape ? add_expr_literal(src, code) : add_expr_escaped(src, code)
      when '=='
        @escape ? add_expr_escaped(src, code) : add_expr_literal(src, code)
      when '==='
        add_expr_debug(src, code)
      end
    end

  end


  #--
  ## (obsolete)
  #module FastEnhancer
  #end
  #++


  ##
  ## use $stdout instead of string
  ##
  ## this is only for Eruby.
  ##
  module StdoutEnhancer

    def self.desc   # :nodoc:
      "use $stdout instead of array buffer or string buffer"
    end

    def add_preamble(src)
      src << "#{@bufvar} = $stdout;"
    end

    def add_postamble(src)
      src << "\n''\n"
    end

  end


  ##
  ## use print statement instead of '_buf << ...'
  ##
  ## this is only for Eruby.
  ##
  module PrintOutEnhancer

    def self.desc   # :nodoc:
      "use print statement instead of '_buf << ...'"
    end

    def add_preamble(src)
    end

    def add_text(src, text)
      src << " print '#{escape_text(text)}';" unless text.empty?
    end

    def add_expr_literal(src, code)
      src << " print((#{code}).to_s);"
    end

    def add_expr_escaped(src, code)
      src << " print #{escaped_expr(code)};"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
    end

  end


  ##
  ## enable print function
  ##
  ## Notice: use Eruby#evaluate() and don't use Eruby#result()
  ## to be enable print function.
  ##
  ## this is only for Eruby.
  ##
  module PrintEnabledEnhancer

    def self.desc   # :nodoc:
      "enable to use print function in '<% %>'"
    end

    def add_preamble(src)
      src << "@_buf = "
      super
    end

    def print(*args)
      args.each do |arg|
        @_buf << arg.to_s
      end
    end

    def evaluate(context=nil)
      _src = @src
      if context.is_a?(Hash)
        context.each do |key, val| instance_variable_set("@#{key}", val) end
      elsif context
        context.instance_variables.each do |name|
          instance_variable_set(name, context.instance_variable_get(name))
        end
      end
      return instance_eval(_src, (@filename || '(erubis)'))
    end

  end


  ##
  ## return array instead of string
  ##
  ## this is only for Eruby.
  ##
  module ArrayEnhancer

    def self.desc   # :nodoc:
      "return array instead of string"
    end

    def add_preamble(src)
      src << "#{@bufvar} = [];"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
      src << "#{@bufvar}\n"
    end

  end


  ##
  ## use an Array object as buffer (included in Eruby by default)
  ##
  ## this is only for Eruby.
  ##
  module ArrayBufferEnhancer

    def self.desc   # :nodoc:
      "use an Array object for buffering (included in Eruby class)"
    end

    def add_preamble(src)
      src << "_buf = [];"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
      src << "_buf.join\n"
    end

  end


  ##
  ## use String class for buffering
  ##
  ## this is only for Eruby.
  ##
  module StringBufferEnhancer

    def self.desc   # :nodoc:
      "use a String object for buffering"
    end

    def add_preamble(src)
      src << "#{@bufvar} = '';"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
      src << "#{@bufvar}.to_s\n"
    end

  end


  ##
  ## use StringIO class for buffering
  ##
  ## this is only for Eruby.
  ##
  module StringIOEnhancer  # :nodoc:

    def self.desc   # :nodoc:
      "use a StringIO object for buffering"
    end

    def add_preamble(src)
      src << "#{@bufvar} = StringIO.new;"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
      src << "#{@bufvar}.string\n"
    end

  end


  ##
  ## set buffer variable name to '_erbout' as well as '_buf'
  ##
  ## this is only for Eruby.
  ##
  module ErboutEnhancer

    def self.desc   # :nodoc:
      "set '_erbout = _buf = \"\";' to be compatible with ERB."
    end

    def add_preamble(src)
      src << "_erbout = #{@bufvar} = '';"
    end

    def add_postamble(src)
      src << "\n" unless src[-1] == ?\n
      src << "#{@bufvar}.to_s\n"
    end

  end


  ##
  ## remove text and leave code, especially useful when debugging.
  ##
  ## ex.
  ##   $ erubis -s -E NoText file.eruby | more
  ##
  ## this is language independent.
  ##
  module NoTextEnhancer

    def self.desc   # :nodoc:
      "remove text and leave code (useful when debugging)"
    end

    def add_text(src, text)
      src << ("\n" * text.count("\n"))
      if text[-1] != ?\n
        text =~ /^(.*?)\z/
        src << (' ' * $1.length)
      end
    end

  end


  ##
  ## remove code and leave text, especially useful when validating HTML tags.
  ##
  ## ex.
  ##   $ erubis -s -E NoCode file.eruby | tidy -errors
  ##
  ## this is language independent.
  ##
  module NoCodeEnhancer

    def self.desc   # :nodoc:
      "remove code and leave text (useful when validating HTML)"
    end

    def add_preamble(src)
    end

    def add_postamble(src)
    end

    def add_text(src, text)
      src << text
    end

    def add_expr(src, code, indicator)
      src << "\n" * code.count("\n")
    end

    def add_stmt(src, code)
      src << "\n" * code.count("\n")
    end

  end


  ##
  ## get convert faster, but spaces around '<%...%>' are not trimmed.
  ##
  ## this is language-independent.
  ##
  module SimplifyEnhancer

    def self.desc   # :nodoc:
      "get convert faster but leave spaces around '<% %>'"
    end

    #DEFAULT_REGEXP = /(^[ \t]*)?<%(=+|\#)?(.*?)-?%>([ \t]*\r?\n)?/m
    SIMPLE_REGEXP = /<%(=+|\#)?(.*?)-?%>/m

    def convert(input)
      src = ""
      add_preamble(src)
      #regexp = pattern_regexp(@pattern)
      pos = 0
      input.scan(SIMPLE_REGEXP) do |indicator, code|
        match = Regexp.last_match
        index = match.begin(0)
        text  = input[pos, index - pos]
        pos   = match.end(0)
        add_text(src, text)
        if !indicator              # <% %>
          add_stmt(src, code)
        elsif indicator[0] == ?\#  # <%# %>
          n = code.count("\n")
          add_stmt(src, "\n" * n)
        else                       # <%= %>
          add_expr(src, code, indicator)
        end
      end
      #rest = $' || input                      # ruby1.8
      rest = pos == 0 ? input : input[pos..-1]  # ruby1.9
      add_text(src, rest)
      add_postamble(src)
      return src
    end

  end


  ##
  ## enable to use other embedded expression pattern (default is '\[= =\]').
  ##
  ## notice! this is an experimental. spec may change in the future.
  ##
  ## ex.
  ##   input = <<END
  ##   <% for item in list %>
  ##     <%= item %> : <%== item %>
  ##     [= item =] : [== item =]
  ##   <% end %>
  ##   END
  ##
  ##   class BiPatternEruby
  ##     include BiPatternEnhancer
  ##   end
  ##   eruby = BiPatternEruby.new(input, :bipattern=>'\[= =\]')
  ##   list = ['<a>', 'b&b', '"c"']
  ##   print eruby.result(binding())
  ##
  ##   ## output
  ##     <a> : &lt;a&gt;
  ##     <a> : &lt;a&gt;
  ##     b&b : b&amp;b
  ##     b&b : b&amp;b
  ##     "c" : &quot;c&quot;
  ##     "c" : &quot;c&quot;
  ##
  ## this is language independent.
  ##
  module BiPatternEnhancer

    def self.desc   # :nodoc:
      "another embedded expression pattern (default '\[= =\]')."
    end

    def initialize(input, properties={})
      self.bipattern = properties[:bipattern]    # or '\$\{ \}'
      super
    end

    ## when pat is nil then '\[= =\]' is used
    def bipattern=(pat)   # :nodoc:
      @bipattern = pat || '\[= =\]'
      pre, post = @bipattern.split()
      @bipattern_regexp = /(.*?)#{pre}(=*)(.*?)#{post}/m
    end

    def add_text(src, text)
      return unless text
      m = nil
      text.scan(@bipattern_regexp) do |txt, indicator, code|
        m = Regexp.last_match
        super(src, txt)
        add_expr(src, code, '=' + indicator)
      end
      #rest = $' || text                    # ruby1.8
      rest = m ? text[m.end(0)..-1] : text  # ruby1.9
      super(src, rest)
    end

  end


  ##
  ## regards lines starting with '^[ \t]*%' as program code
  ##
  ## in addition you can specify prefix character (default '%')
  ##
  ## this is language-independent.
  ##
  module PrefixedLineEnhancer

    def self.desc   # :nodoc:
      "regard lines matched to '^[ \t]*%' as program code"
    end

    def init_generator(properties={})
      super
      @prefixchar = properties[:prefixchar]
    end

    def add_text(src, text)
      unless @prefixrexp
        @prefixchar ||= '%'
        @prefixrexp = Regexp.compile("^([ \\t]*)\\#{@prefixchar}(.*?\\r?\\n)")
      end
      pos = 0
      text2 = ''
      text.scan(@prefixrexp) do
        space = $1
        line  = $2
        space, line = '', $1 unless $2
        match = Regexp.last_match
        len   = match.begin(0) - pos
        str   = text[pos, len]
        pos   = match.end(0)
        if text2.empty?
          text2 = str
        else
          text2 << str
        end
        if line[0, 1] == @prefixchar
          text2 << space << line
        else
          super(src, text2)
          text2 = ''
          add_stmt(src, space + line)
        end
      end
      #rest = pos == 0 ? text : $'             # ruby1.8
      rest = pos == 0 ? text : text[pos..-1]   # ruby1.9
      unless text2.empty?
        text2 << rest if rest
        rest = text2
      end
      super(src, rest)
    end

  end


  ##
  ## regards lines starting with '%' as program code
  ##
  ## this is for compatibility to eruby and ERB.
  ##
  ## this is language-independent.
  ##
  module PercentLineEnhancer
    include PrefixedLineEnhancer

    def self.desc   # :nodoc:
      "regard lines starting with '%' as program code"
    end

    #--
    #def init_generator(properties={})
    #  super
    #  @prefixchar = '%'
    #  @prefixrexp = /^\%(.*?\r?\n)/
    #end
    #++

    def add_text(src, text)
      unless @prefixrexp
        @prefixchar = '%'
        @prefixrexp = /^\%(.*?\r?\n)/
      end
      super(src, text)
    end

  end


  ##
  ## [experimental] allow header and footer in eRuby script
  ##
  ## ex.
  ##   ====================
  ##   ## without header and footer
  ##   $ cat ex1.eruby
  ##   <% def list_items(list) %>
  ##   <%   for item in list %>
  ##   <li><%= item %></li>
  ##   <%   end %>
  ##   <% end %>
  ##
  ##   $ erubis -s ex1.eruby
  ##   _buf = []; def list_items(list)
  ##   ;   for item in list
  ##   ; _buf << '<li>'; _buf << ( item ).to_s; _buf << '</li>
  ##   ';   end
  ##   ; end
  ##   ;
  ##   _buf.join
  ##
  ##   ## with header and footer
  ##   $ cat ex2.eruby
  ##   <!--#header:
  ##   def list_items(list)
  ##    #-->
  ##   <%  for item in list %>
  ##   <li><%= item %></li>
  ##   <%  end %>
  ##   <!--#footer:
  ##   end
  ##    #-->
  ##
  ##   $ erubis -s -c HeaderFooterEruby ex4.eruby
  ##
  ##   def list_items(list)
  ##    _buf = []; _buf << '
  ##   ';  for item in list
  ##   ; _buf << '<li>'; _buf << ( item ).to_s; _buf << '</li>
  ##   ';  end
  ##   ; _buf << '
  ##   ';
  ##   _buf.join
  ##   end
  ##
  ##   ====================
  ##
  ## this is language-independent.
  ##
  module HeaderFooterEnhancer

    def self.desc   # :nodoc:
      "allow header/footer in document (ex. '<!--#header: #-->')"
    end

    HEADER_FOOTER_PATTERN = /(.*?)(^[ \t]*)?<!--\#(\w+):(.*?)\#-->([ \t]*\r?\n)?/m

    def add_text(src, text)
      m = nil
      text.scan(HEADER_FOOTER_PATTERN) do |txt, lspace, word, content, rspace|
        m = Regexp.last_match
        flag_trim = @trim && lspace && rspace
        super(src, txt)
        content = "#{lspace}#{content}#{rspace}" if flag_trim
        super(src, lspace) if !flag_trim && lspace
        instance_variable_set("@#{word}", content)
        super(src, rspace) if !flag_trim && rspace
      end
      #rest = $' || text                    # ruby1.8
      rest = m ? text[m.end(0)..-1] : text  # ruby1.9
      super(src, rest)
    end

    attr_accessor :header, :footer

    def convert(input)
      source = super
      return @src = "#{@header}#{source}#{@footer}"
    end

  end


  ##
  ## delete indentation of HTML.
  ##
  ## this is language-independent.
  ##
  module DeleteIndentEnhancer

    def self.desc   # :nodoc:
      "delete indentation of HTML."
    end

    def convert_input(src, input)
      input = input.gsub(/^[ \t]+</, '<')
      super(src, input)
    end

  end


  ##
  ## convert "<h1><%=title%></h1>" into "_buf << %Q`<h1>#{title}</h1>`"
  ##
  ## this is only for Eruby.
  ##
  module InterpolationEnhancer

    def self.desc   # :nodoc:
      "convert '<p><%=text%></p>' into '_buf << %Q`<p>\#{text}</p>`'"
    end

    def convert_input(src, input)
      pat = @pattern
      regexp = pat.nil? || pat == '<% %>' ? Basic::Converter::DEFAULT_REGEXP : pattern_regexp(pat)
      pos = 0
      is_bol = true     # is beginning of line
      str = ''
      input.scan(regexp) do |indicator, code, tailch, rspace|
        match = Regexp.last_match()
        len  = match.begin(0) - pos
        text = input[pos, len]
        pos  = match.end(0)
        ch   = indicator ? indicator[0] : nil
        lspace = ch == ?= ? nil : detect_spaces_at_bol(text, is_bol)
        is_bol = rspace ? true : false
        _add_text_to_str(str, text)
        ## * when '<%= %>', do nothing
        ## * when '<% %>' or '<%# %>', delete spaces iff only spaces are around '<% %>'
        if ch == ?=              # <%= %>
          rspace = nil if tailch && !tailch.empty?
          str << lspace if lspace
          add_expr(str, code, indicator)
          str << rspace if rspace
        elsif ch == ?\#          # <%# %>
          n = code.count("\n") + (rspace ? 1 : 0)
          if @trim && lspace && rspace
            add_text(src, str)
            str = ''
            add_stmt(src, "\n" * n)
          else
            str << lspace if lspace
            add_text(src, str)
            str = ''
            add_stmt(src, "\n" * n)
            str << rspace if rspace
          end
        else                     # <% %>
          if @trim && lspace && rspace
            add_text(src, str)
            str = ''
            add_stmt(src, "#{lspace}#{code}#{rspace}")
          else
            str << lspace if lspace
            add_text(src, str)
            str = ''
            add_stmt(src, code)
            str << rspace if rspace
          end
        end
      end
      #rest = $' || input                       # ruby1.8
      rest = pos == 0 ? input : input[pos..-1]  # ruby1.9
      _add_text_to_str(str, rest)
      add_text(src, str)
    end

    def add_text(src, text)
      return if !text || text.empty?
      #src << " _buf << %Q`" << text << "`;"
      if text[-1] == ?\n
        text[-1] = "\\n"
        src << " #{@bufvar} << %Q`#{text}`\n"
      else
        src << " #{@bufvar} << %Q`#{text}`;"
      end
    end

    def _add_text_to_str(str, text)
      return if !text || text.empty?
      str << text.gsub(/[`\#\\]/, '\\\\\&')
    end

    def add_expr_escaped(str, code)
      str << "\#{#{escaped_expr(code)}}"
    end

    def add_expr_literal(str, code)
      str << "\#{#{code}}"
    end

  end


end
