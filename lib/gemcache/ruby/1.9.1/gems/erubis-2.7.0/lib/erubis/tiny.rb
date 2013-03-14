##
## $Release: 2.7.0 $
## copyright(c) 2006-2011 kuwata-lab.com all rights reserved.
##

module Erubis

  ##
  ## tiny and the simplest implementation of eRuby
  ##
  ## ex.
  ##   eruby = TinyEruby.new(File.read('example.rhtml'))
  ##   print eruby.src                 # print ruby code
  ##   print eruby.result(binding())   # eval ruby code with Binding object
  ##   print eruby.evalute(context)    # eval ruby code with context object
  ##
  class TinyEruby

    def initialize(input=nil)
      @src = convert(input) if input
    end
    attr_reader :src

    EMBEDDED_PATTERN = /<%(=+|\#)?(.*?)-?%>/m

    def convert(input)
      src = "_buf = '';"           # preamble
      pos = 0
      input.scan(EMBEDDED_PATTERN) do |indicator, code|
        m = Regexp.last_match
        text = input[pos...m.begin(0)]
        pos  = m.end(0)
        #src << " _buf << '" << escape_text(text) << "';"
        text.gsub!(/['\\]/, '\\\\\&')
        src << " _buf << '" << text << "';" unless text.empty?
        if !indicator              # <% %>
          src << code << ";"
        elsif indicator == '#'     # <%# %>
          src << ("\n" * code.count("\n"))
        else                       # <%= %>
          src << " _buf << (" << code << ").to_s;"
        end
      end
      #rest = $' || input                        # ruby1.8
      rest = pos == 0 ? input : input[pos..-1]   # ruby1.9
      #src << " _buf << '" << escape_text(rest) << "';"
      rest.gsub!(/['\\]/, '\\\\\&')
      src << " _buf << '" << rest << "';" unless rest.empty?
      src << "\n_buf.to_s\n"       # postamble
      return src
    end

    #def escape_text(text)
    #  return text.gsub!(/['\\]/, '\\\\\&') || text
    #end

    def result(_binding=TOPLEVEL_BINDING)
      eval @src, _binding
    end

    def evaluate(_context=Object.new)
      if _context.is_a?(Hash)
        _obj = Object.new
        _context.each do |k, v| _obj.instance_variable_set("@#{k}", v) end
        _context = _obj
      end
      _context.instance_eval @src
    end

  end



  module PI
  end

  class PI::TinyEruby

    def initialize(input=nil, options={})
      @escape  = options[:escape] || 'Erubis::XmlHelper.escape_xml'
      @src = convert(input) if input
    end

    attr_reader :src

    EMBEDDED_PATTERN = /(^[ \t]*)?<\?rb(\s.*?)\?>([ \t]*\r?\n)?|@(!+)?\{(.*?)\}@/m

    def convert(input)
      src = "_buf = '';"           # preamble
      pos = 0
      input.scan(EMBEDDED_PATTERN) do |lspace, stmt, rspace, indicator, expr|
        match = Regexp.last_match
        len   = match.begin(0) - pos
        text  = input[pos, len]
        pos   = match.end(0)
        #src << " _buf << '" << escape_text(text) << "';"
        text.gsub!(/['\\]/, '\\\\\&')
        src << " _buf << '" << text << "';" unless text.empty?
        if stmt                # <?rb ... ?>
          if lspace && rspace
            src << "#{lspace}#{stmt}#{rspace}"
          else
            src << " _buf << '" << lspace << "';" if lspace
            src << stmt << ";"
            src << " _buf << '" << rspace << "';" if rspace
          end
        else                       # ${...}, $!{...}
          if !indicator
            src << " _buf << " << @escape << "(" << expr << ");"
          elsif indicator == '!'
            src << " _buf << (" << expr << ").to_s;"
          end
        end
      end
      #rest = $' || input                        # ruby1.8
      rest = pos == 0 ? input : input[pos..-1]   # ruby1.9
      #src << " _buf << '" << escape_text(rest) << "';"
      rest.gsub!(/['\\]/, '\\\\\&')
      src << " _buf << '" << rest << "';" unless rest.empty?
      src << "\n_buf.to_s\n"       # postamble
      return src
    end

    #def escape_text(text)
    #  return text.gsub!(/['\\]/, '\\\\\&') || text
    #end

    def result(_binding=TOPLEVEL_BINDING)
      eval @src, _binding
    end

    def evaluate(_context=Object.new)
      if _context.is_a?(Hash)
        _obj = Object.new
        _context.each do |k, v| _obj.instance_variable_set("@#{k}", v) end
        _context = _obj
      end
      _context.instance_eval @src
    end

  end


end
