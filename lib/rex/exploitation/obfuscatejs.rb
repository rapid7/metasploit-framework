# -*- coding: binary -*-
require 'rex/text'
module Rex
module Exploitation

#
# Obfuscates javascript in various ways
#
class ObfuscateJS
  attr_reader :opts

  #
  # Obfuscates a javascript string.
  #
  # Options are 'Symbols', described below, and 'Strings', a boolean
  # which specifies whether strings within the javascript should be
  # mucked with (defaults to false).
  #
  # The 'Symbols' argument should have the following format:
  #
  #   {
  #      'Variables'  => [ 'var1', ... ],
  #      'Methods'    => [ 'method1', ... ],
  #      'Namespaces' => [ 'n', ... ],
  #      'Classes'    => [ { 'Namespace' => 'n', 'Class' => 'y'}, ... ]
  #   }
  #
  # Make sure you order your methods, classes, and namespaces by most
  # specific to least specific to prevent partial substitution.  For
  # instance, if you have two methods (joe and joeBob), you should place
  # joeBob before joe because it is more specific and will be globally
  # replaced before joe is replaced.
  #
  # A simple example follows:
  #
  # <code>
  # js = ObfuscateJS.new <<ENDJS
  #     function say_hi() {
  #         var foo = "Hello, world";
  #         document.writeln(foo);
  #     }
  # ENDJS
  # js.obfuscate(
  #     'Symbols' => {
  #	       'Variables' => [ 'foo' ],
  #	       'Methods'   => [ 'say_hi' ]
  #	  }
  #     'Strings' => true
  # )
  # </code>
  #
  # which should generate something like the following:
  #
  # <code>
  # function oJaDYRzFOyJVQCOHk() { var cLprVG = "\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64"; document.writeln(cLprVG); }
  # </code>
  #
  # String obfuscation tries to deal with escaped quotes within strings but
  # won't catch things like
  #     "\\"
  # so be careful.
  #
  def self.obfuscate(js, opts = {})
    ObfuscateJS.new(js).obfuscate(opts)
  end

  #
  # Initialize an instance of the obfuscator
  #
  def initialize(js = "", opts = {})
    @js      = js
    @dynsym  = {}
    @opts    = {
      'Symbols' => {
        'Variables'=>[],
        'Methods'=>[],
        'Namespaces'=>[],
        'Classes'=>[]
      },
      'Strings'=>false
    }
    @done = false
    update_opts(opts) if (opts.length > 0)
  end

  def update_opts(opts)
    if (opts.nil? or opts.length < 1)
      return
    end
    if (@opts['Symbols'] && opts['Symbols'])
      ['Variables', 'Methods', 'Namespaces', 'Classes'].each { |k|
        if (@opts['Symbols'][k] && opts['Symbols'][k])
          opts['Symbols'][k].each { |s|
            if (not @opts['Symbols'][k].include? s)
              @opts['Symbols'][k].push(s)
            end
          }
        elsif (opts['Symbols'][k])
          @opts['Symbols'][k] = opts['Symbols'][k]
        end
      }
    elsif opts['Symbols']
      @opts['Symbols'] = opts['Symbols']
    end
    @opts['Strings'] ||= opts['Strings']
  end

  #
  # Returns the dynamic symbol associated with the supplied symbol name
  #
  # If obfuscation has not yet been performed (i.e. obfuscate() has not been
  # called), then this method simply returns its argument
  #
  def sym(name)
    @dynsym[name] || name
  end

  #
  # Obfuscates the javascript string passed to the constructor
  #
  def obfuscate(opts = {})
    #return @js if (@done)
    @done = true

    update_opts(opts)

    if (@opts['Strings'])
      obfuscate_strings()

      # Full space randomization does not work for javascript -- despite
      # claims that space is irrelavent, newlines break things.  Instead,
      # use only space (0x20) and tab (0x09).

      #@js.gsub!(/[\x09\x20]+/) { |s|
      #	len = rand(50)+2
      #	set = "\x09\x20"
      #	buf = ''
      #	while (buf.length < len)
      #		buf << set[rand(set.length)].chr
      #	end
      #
      #	buf
      #}
    end

    # Remove our comments
    remove_comments

    # Globally replace symbols
    replace_symbols(@opts['Symbols']) if @opts['Symbols']

    return @js
  end

  #
  # Returns the replaced javascript string
  #
  def to_s
    @js
  end
  alias :to_str :to_s

  def <<(str)
    @js << str
  end
  def +(str)
    @js + str
  end

protected
  attr_accessor :done

  #
  # Get rid of both single-line C++ style comments and multiline C style comments.
  #
  # Note: embedded comments (e.g.: "/*/**/*/") will break this,
  # but they also break real javascript engines so I don't care.
  #
  def remove_comments
    @js.gsub!(%r{\s+//.*$}, '')
    @js.gsub!(%r{/\*.*?\*/}m, '')
  end

  # Replace method, class, and namespace symbols found in the javascript
  # string
  def replace_symbols(symbols)
    taken = { }

    # Generate random symbol names
    [ 'Variables', 'Methods', 'Classes', 'Namespaces' ].each { |symtype|
      next if symbols[symtype].nil?
      symbols[symtype].each { |sym|
        dyn = Rex::Text.rand_text_alpha(rand(32)+1) until dyn and not taken.key?(dyn)

        taken[dyn] = true

        if symtype == 'Classes'
          full_sym = sym['Namespace'] + "." + sym['Class']
          @dynsym[full_sym] = dyn

          @js.gsub!(/#{full_sym}/) { |m|
            sym['Namespace'] + "." + dyn
          }
        else
          @dynsym[sym] = dyn

          @js.gsub!(/#{sym}/, dyn)
        end
      }
    }
  end

  #
  # Change each string into some javascript that will generate that string
  #
  # There are a couple of caveats to using string obfuscation:
  #   * it tries to deal with escaped quotes within strings but won't catch
  #     things like: "\\"
  #   * depending on the random choices, this can easily balloon a short
  #     string up to hundreds of kilobytes if called multiple times.
  # so be careful.
  #
  def obfuscate_strings()
    @js.gsub!(/".*?[^\\]"|'.*?[^\\]'/) { |str|
      buf = ''
      quote = str[0,1]
      # Pull the quotes off either end
      str = str[1, str.length-2]
      case (rand(2))
      # Disable hex encoding for now.  It's just too big a hassle.
      #when 0
      #	# This is where we can run into trouble with generating
      #	# incorrect code.  If we hex encode a string twice, the second
      #	# encoding will generate the first instead of the original
      #	# string.
      #	if str =~ /\\x/
      #		# Always have to remove spaces from strings so the space
      #		# randomization doesn't mess with them.
      #		buf = quote + str.gsub(/ /, '\x20') + quote
      #	else
      #		buf = '"' + Rex::Text.to_hex(str) + '"'
      #	end
      when 0
        #
        # Escape sequences when naively encoded for unescape become a
        # literal backslash instead of the intended meaning.  To avoid
        # that problem, we scan the string for escapes and leave them
        # unmolested.
        #
        buf << 'unescape("'
        bytes = str.unpack("C*")
        c = 0
        while bytes[c]
          if bytes[c].chr == "\\"
            # XXX This is pretty slow.
            esc_len = parse_escape(bytes, c)
            buf << bytes[c, esc_len].map{|a| a.chr}.join
            c += esc_len
            next
          end
          buf << "%%%0.2x"%(bytes[c])
          # Break the string into smaller strings
          if bytes[c+1] and rand(10) == 0
            buf << '" + "'
          end
          c += 1
        end
        buf << '")'
      when 1
        buf = "String.fromCharCode( "
        bytes = str.unpack("C*")
        c = 0
        while bytes[c]
          if bytes[c].chr == "\\"
            case bytes[c+1].chr
            # For chars that contain their non-escaped selves, step
            # past the backslash and let the rand() below decide
            # how to represent the character.
            when '"'; c += 1
            when "'"; c += 1
            when "\\"; c += 1
            # For others, just take the hex representation out of
            # laziness.
            when "n"; buf << "0x0a"; c += 2; next
            when "t"; buf << "0x09"; c += 2; next
            # Lastly, if it's a hex, unicode, or octal escape,
            # leave it, and anything after it, alone.  At some
            # point we may want to parse up to the end of the
            # escapes and encode subsequent non-escape characters.
            # Since this is the lazy way to do it, spaces after an
            # escape sequence will get away unmodified.  To prevent
            # the space randomizer from hosing the string, convert
            # spaces specifically.
            else
              buf = buf[0,buf.length-1] + " )"
              buf << ' + ("' + bytes[c, bytes.length].map{|a| a==0x20 ? '\x20' : a.chr}.join + '" '
              break
            end
          end
          case (rand(3))
          when 0
            buf << " %i,"%(bytes[c])
          when 1
            buf << " 0%o,"%(bytes[c])
          when 2
            buf << " 0x%0.2x,"%(bytes[c])
          end
          c += 1
        end
        # Strip off the last comma
        buf = buf[0,buf.length-1] + " )"
      end
      buf
    }
    @js
  end

  def parse_escape(bytes, offset)
    esc_len = 0
    if bytes[offset].chr == "\\"
      case bytes[offset+1].chr
      when "u"; esc_len = 6     # unicode \u1234
      when "x"; esc_len = 4     # hex, \x41
      when /[0-9]/              # octal, \123, \0
        oct = bytes[offset+1, 4].map{|a|a.chr}.join
        oct =~ /([0-9]+)/
        esc_len = 1 + $1.length
      else; esc_len = 2         # \" \n, etc.
      end
    end
    esc_len
  end
end

end
end
