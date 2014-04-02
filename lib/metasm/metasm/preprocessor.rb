#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'


module Metasm
# A source text preprocessor (C-like)
# defines the methods nexttok, readtok and unreadtok
# they spits out Tokens of type :
#  :string for words (/[a-Z0-9$_]+/)
#  :punct for punctuation (/[.,:*+-]/ etc), any unhandled character
#  :space for space/tabs/comment/\r
#  :eol for newline :space including at least one \n not escaped
#  :quoted for quoted string, tok.raw includes delimiter and all content. tok.value holds the interpreted value (handles \x, \oct, \r etc). 1-line only
# or nil on end of stream
# \ at end of line discards a newline, otherwise returns a tok :punct with the \
# preprocessor directives start with a :punct '#' just after an :eol (so you can have spaces before #), they take a whole line
# comments are C/C++ style (//...\n or /*...*/), returned as :eol (resp. :space)
class Preprocessor
  # a token, as returned by the preprocessor
  class Token
    # the token type: :space, :eol, :quoted, :string, :punct, ...
    attr_accessor :type
    # the interpreted value of the token (Integer for an int, etc)
    attr_accessor :value
    # the raw string that gave this token
    attr_accessor :raw
    # a list of token this on is expanded from (Preprocessor macro expansion)
    attr_accessor :expanded_from

    include Backtrace

    def initialize(backtrace)
      @backtrace = backtrace
      @value = nil
      @raw = ''
    end

    # used when doing 'raise tok, "foo"'
    # raises a ParseError, adding backtrace information
    def exception(msg='syntax error')
      msgh = msg.to_s
      if msg
        msgh << ' near '
        expanded_from.to_a.each { |ef| msgh << ef.exception(nil).message << " expanded to \n\t"  }
      end
      msgh << ((@raw.length > 35) ? (@raw[0..10] + '<...>' + @raw[-10..-1]).inspect : @raw.inspect)
      msgh << " at " << backtrace_str
      ParseError.new msgh
    end

    def dup
      n = self.class.new(backtrace)
      n.type = @type
      n.value = @value.kind_of?(String) ? @value.dup : @value
      n.raw = @raw.dup
      n.expanded_from = @expanded_from.dup if defined? @expanded_from
      n
    end
  end

  # a preprocessor macro
  class Macro
    # the token holding the name used in the macro definition
    attr_accessor :name
    # array of tokens of formal arguments
    attr_accessor :args
    # array of tokens of macro body
    attr_accessor :body
    # bool
    attr_accessor :varargs

    def initialize(name)
      @name = name
      @body = []
    end


    # parses an argument list from the lexer or from a list of tokens
    # modifies the list, returns an array of list of tokens/nil
    # handles nesting
    def self.parse_arglist(lexer, list=nil)
      readtok = lambda { list ? list.shift : lexer.readtok_nopp }
      unreadtok = lambda { |t| list ? (list.unshift(t) if t) : lexer.unreadtok(t) }
      tok = nil
      unreadlist = []
      unreadlist << tok while tok = readtok[] and tok.type == :space
      if not tok or tok.type != :punct or tok.raw != '('
        unreadtok[tok]
        unreadlist.reverse_each { |t| unreadtok[t] }
        return nil
      end
      args = []
      # each argument is any token sequence
      # if it includes an '(' then find the matching ')', whatever is inside (handle nesting)
      # arg cannot include ',' in the top-level
      # args are parsed with no macro expansion
      # convert any space/eol sequence to a single space, strips them at begin/end of argument
      loop do
        arg = []
        nest = 0
        loop do
          raise lexer, 'unterminated arg list' if not tok = readtok[]
          case tok.type
          when :eol, :space
            next if arg.last and arg.last.type == :space
            tok = tok.dup
            tok.type = :space
            tok.raw = ' '
          when :punct
            case tok.raw
            when ','; break if nest == 0
            when ')'; break if nest == 0 ; nest -= 1
            when '('; nest += 1
            end
          end
          arg << tok
        end
        arg.pop if arg.last and arg.last.type == :space
        args << arg if not arg.empty? or args.length > 0 or tok.raw != ')'
        break if tok.raw == ')'
      end
      args
    end

    # applies a preprocessor macro
    # parses arguments if needed
    # macros are lazy
    # fills tokens.expanded_from
    # returns an array of tokens
    def apply(lexer, name, args, list=nil)
      expfrom = name.expanded_from.to_a + [name]
      if args
        # hargs is a hash argname.raw => array of tokens
        hargs = @args.zip(args).inject({}) { |h, (af, ar)| h.update af.raw => ar }

        if not varargs
          raise name, 'invalid argument count' if args.length != @args.length
        else
          raise name, 'invalid argument count' if args.length < @args.length
          virg = name.dup		# concat remaining args in __VA_ARGS__
          virg.type = :punct
          virg.raw = ','
          va = args[@args.length..-1].map { |a| a + [virg.dup] }.flatten
          va.pop
          hargs['__VA_ARGS__'] = va
        end
      else
        hargs = {}
      end

      res = []
      b = @body.map { |t| t = t.dup ; t.expanded_from = expfrom ; t }
      while t = b.shift
        if a = hargs[t.raw]
          # expand macros
          a = a.dup
          while at = a.shift
            margs = nil
            if at.type == :string and am = lexer.definition[at.raw] and not at.expanded_from.to_a.find { |ef| ef.raw == @name.raw } and
                ((am.args and margs = Macro.parse_arglist(lexer, a)) or not am.args)
              toks = am.apply(lexer, at, margs, a)
              a = toks + a	# reroll
            else
              res << at.dup if not res.last or res.last.type != :space or at.type != :space
            end
          end
        elsif t.type == :punct and t.raw == '##'
          # the '##' operator: concat the next token to the last in body
          nil while t = b.shift and t.type == :space
          res.pop while res.last and res.last.type == :space
          if not a = hargs[t.raw]
            a = [t]
          end
          if varargs and t.raw == '__VA_ARGS__' and res.last and res.last.type == :punct and res.last.raw == ','
            if args.length == @args.length # pop last , if no vararg passed # XXX poof(1, 2,) != poof(1, 2)
              res.pop
            else # allow merging with ',' without warning
              res.concat a
            end
          else
            a = a[1..-1] if a.first and a.first.type == :space
            if not res.last or res.last.type != :string or not a.first or a.first.type != :string
              puts name.exception("cannot merge token #{res.last.raw} with #{a.first ? a.first.raw : 'nil'}").message if not a.first or (a.first.raw != '.' and res.last.raw != '.') if $VERBOSE
              res.concat a
            else
              res[-1] = res[-1].dup
              res.last.raw << a.first.raw
              res.concat a[1..-1]
            end
          end
        elsif args and t.type == :punct and t.raw == '#' # map an arg to a qstring
          nil while t = b.shift and t.type == :space
          t.type = :quoted
          t.value = hargs[t.raw].map { |aa| aa.raw }.join
          t.value = t.value[1..-1] if t.value[0] == ?\ 	# delete leading space
          t.raw = t.value.inspect
          res << t
        else
          res << t
        end
      end
      res
    end

    # parses the argument list and the body from lexer
    # converts # + # to ## in body
    def parse_definition(lexer)
      varg = nil
      if tok = lexer.readtok_nopp and tok.type == :punct and tok.raw == '('
        @args = []
        loop do
          nil while tok = lexer.readtok_nopp and tok.type == :space
          # check '...'
          if tok and tok.type == :punct and tok.raw == '.'
            t1 = lexer.readtok_nopp
            t2 = lexer.readtok_nopp
            t3 = lexer.readtok_nopp
            t3 = lexer.readtok_nopp while t3 and t3.type == :space
            raise @name, 'booh'  if not t1 or t1.type != :punct or t1.raw != '.' or
                  not t2 or t2.type != :punct or t2.raw != '.' or
                  not t3 or t3.type != :punct or t3.raw != ')'
            @varargs = true
            break
          end
          break if tok and tok.type == :punct and tok.raw == ')' and @args.empty?	# allow empty list
          raise @name, 'invalid arg definition' if not tok or tok.type != :string
          @args << tok
          nil while tok = lexer.readtok_nopp and tok.type == :space
          # check '...'
          if tok and tok.type == :punct and tok.raw == '.'
            t1 = lexer.readtok_nopp
            t2 = lexer.readtok_nopp
            t3 = lexer.readtok_nopp
            t3 = lexer.readtok_nopp while t3 and t3.type == :space
            raise @name, 'booh'  if not t1 or t1.type != :punct or t1.raw != '.' or
                  not t2 or t2.type != :punct or t2.raw != '.' or
                  not t3 or t3.type != :punct or t3.raw != ')'
            @varargs = true
            varg = @args.pop.raw
            break
          end
          raise @name, 'invalid arg separator' if not tok or tok.type != :punct or (tok.raw != ')' and tok.raw != ',')
          break if tok.raw == ')'
        end
      else lexer.unreadtok tok
      end

      nil while tok = lexer.readtok_nopp and tok.type == :space
      lexer.unreadtok tok

      while tok = lexer.readtok_nopp
        tok = tok.dup
        case tok.type
        when :eol
          lexer.unreadtok tok
          break
        when :space
          next if @body.last and @body.last.type == :space
          tok.raw = ' '
        when :string
          tok.raw = '__VA_ARGS__' if varg and tok.raw == varg
        when :punct
          if tok.raw == '#'
            ntok = lexer.readtok_nopp
            if ntok and ntok.type == :punct and ntok.raw == '#'
              tok.raw << '#'
            else
              lexer.unreadtok ntok
            end
          end
        end
        @body << tok
      end
      @body.pop if @body.last and @body.last.type == :space

      # check macro is correct
      invalid_body = nil
      if (@body[-1] and @body[-1].raw == '##') or (@body[0] and @body[0].raw == '##')
        invalid_body ||= 'cannot have ## at begin or end of macro body'
      end
      if args
        if @args.map { |a| a.raw }.uniq.length != @args.length
          invalid_body ||= 'duplicate macro parameter'
        end
        @body.each_with_index { |tok_, i|
          if tok_.type == :punct and tok_.raw == '#'
            a = @body[i+1]
            a = @body[i+2] if not a or a.type == :space
            if not a.type == :string or (not @args.find { |aa| aa.raw == a.raw } and (not varargs or a.raw != '__VA_ARGS__'))
              invalid_body ||= 'cannot have # followed by non-argument'
            end
          end
        }
      end
      if invalid_body
        puts "W: #{lexer.filename}:#{lexer.lineno}, in #{@name.raw}: #{invalid_body}" if $VERBOSE
        false
      else
        true
      end
    end

    def dump(comment = true)
      str = ''
      str << "\n// from #{@name.backtrace[-2, 2] * ':'}\n" if comment
      str << "#define #{@name.raw}"
      if args
        str << '(' << (@args.map { |t| t.raw } + (varargs ? ['...'] : [])).join(', ') << ')'
      end
      str << ' ' << @body.map { |t| t.raw }.join
    end
  end

  # special object, handles __FILE__ __LINE__ __COUNTER__ __DATE__ __TIME__ macros
  class SpecialMacro
    def args ; end
    def body ; [@name] end

    attr_accessor :name
    def initialize(raw)
      @name = Token.new(nil)
      @name.type = :string
      @name.raw = raw
    end

    def apply(lexer, name, emptyarglist, toklist=nil)
      tok = @name.dup
      tok.expanded_from = name.expanded_from.to_a + [name]
      case @name.raw
      when '__FILE__', '__DATE__', '__TIME__'	# returns a :quoted
        tok.type = :quoted
        tok.value = \
        case @name.raw
        when '__FILE__'
          name = name.expanded_from.first if name.expanded_from
          name.backtrace.to_a[-2].to_s
        when '__DATE__'; Time.now.strftime('%b %e %Y')
        when '__TIME__'; Time.now.strftime('%H:%M:%S')
        end
        tok.raw = tok.value.inspect
      when '__LINE__', '__COUNTER__'		# returns a :string
        tok.type = :string
        case @name.raw
        when '__LINE__'
          name = name.expanded_from.first if name.expanded_from
          tok.value = name.backtrace.to_a[-1]
        when '__COUNTER__'
          tok.value = @counter ||= 0
          @counter += 1
        end
        tok.raw = tok.value.to_s
      else raise name, 'internal error'
      end
      [tok]
    end
  end

  # the raw string we're reading
  attr_accessor :text, :pos
  # the backtrace information for current file
  attr_accessor :filename, :lineno
  # the unreadtok queue
  attr_accessor :queue
  # the backtrace (array of previous [filename, lineno, text, pos] that #included us)
  attr_accessor :backtrace
  # a hash of macro definitions: macro name => [macro def tok, [macro args tok], [macro body toks]]
  attr_accessor :definition
  # array of directories to search for #included <files>
  attr_accessor :include_search_path
  # a Proc called for unhandled #pragma occurences
  # takes the pragma 1st tok as arg, must unread the final :eol, should fallback to the previous callback
  attr_accessor :pragma_callback
  # hash filename => file content
  attr_accessor :hooked_include
  attr_accessor :warn_redefinition
  attr_accessor :may_preprocess

  # global default search directory for #included <files>
  @@include_search_path = ['/usr/include']
  def self.include_search_path ; @@include_search_path end
  def self.include_search_path=(np) @@include_search_path=np end

  def initialize(text='')
    @backtrace = []
    @definition = %w[__FILE__ __LINE__ __COUNTER__ __DATE__ __TIME__].inject({}) { |h, n| h.update n => SpecialMacro.new(n) }
    @include_search_path = @@include_search_path.dup
    # stack of :accept/:discard/:discard_all/:testing, represents the current nesting of #if..#endif
    @ifelse_nesting = []
    @warn_redefinition = true
    @hooked_include = {}
    @may_preprocess = false
    @pragma_once = {}
    @pragma_callback = lambda { |otok|
      tok = otok
      str = tok.raw.dup
      str << tok.raw while tok = readtok and tok.type != :eol
      unreadtok tok
      puts otok.exception("unhandled pragma #{str.inspect}").message if $VERBOSE
    }
    feed!(text)
    define '__METASM__', VERSION
  end

  def exception(msg='syntax error')
    backtrace_str = Backtrace.backtrace_str([@filename, @lineno] + @backtrace.map { |f, l, *a| [f, l] }.flatten)
    ParseError.new "at #{backtrace_str}: #{msg}"
  end

  # returns the preprocessed content
  def dump
    ret = ''
    neol = 0
    while not eos?
      t = readtok
      case t.type
      when :space; ret << ' '
      when :eol; ret << "\n" if (neol += 1) <= 2
      when :quoted; neol = 0 ; ret << t.raw	# keep quoted style
      else neol = 0 ; ret << (t.value || t.raw).to_s
      end
    end
    ret
  end

  attr_accessor :traced_macros
  # preprocess text, and retrieve all macros defined in #included <files> and used in the text
  # returns a C source-like string
  def self.factorize(text, comment=false)
    p = new(text)
    p.traced_macros = []
    p.readtok while not p.eos?
    p.dump_macros(p.traced_macros, comment)
  end

  # dumps the definition of the macros whose name is in the list + their dependencies
  # returns one big C-style source string
  def dump_macros(list, comment = true)
    depend = {}
    # build dependency graph (we can output macros in any order, but it's more human-readable)
    walk = lambda { |mname|
      depend[mname] ||= []
      @definition[mname].body.each { |t|
        name = t.raw
        if @definition[name]
          depend[mname] << name
          if not depend[name]
            depend[name] = []
            walk[name]
          end
        end
      }
    }
    list.each { |mname| walk[mname] }

    res = []
    while not depend.empty?
      todo_now = depend.keys.find_all { |k| (depend[k] - [k]).empty? }
      if todo_now.empty?
        dep_cycle = lambda { |ary|
          deps = depend[ary.last]
          if deps.include? ary.first; ary
          elsif (deps-ary).find { |d| deps = dep_cycle[ary + [d]] }; deps
          end
        }
        if not depend.find { |k, dep| todo_now = dep_cycle[[k]] }
          todo_now = depend.keys
        end
      end
      todo_now.sort.each { |k|
        res << @definition[k].dump(comment) if @definition[k].kind_of? Macro
        depend.delete k
      }
      depend.each_key { |k| depend[k] -= todo_now }
    end
    res.join("\n")
  end

  # starts a new lexer, with the specified initial filename/line number (for backtraces)
  def feed(text, filename='unknown', lineno=1)
    raise self, 'cannot start new text, did not finish current source' if not eos?
    feed!(text, filename, lineno)
  end

  # starts a new lexer, with the specified initial filename/line number (for backtraces)
  # discards old text/whatever
  def feed!(text, filename='unknown', lineno=1)
    raise ArgumentError, 'need something to parse!' if not text
    @text = text
    if not @may_preprocess and (@text =~ /^\s*(#|\?\?=)/ or (not @definition.empty? and
         @text =~ /#{@definition.keys.map { |k| Regexp.escape(k) }.join('|')}/))
      @may_preprocess = true
    end
    # @filename[-1] used in trace_macros to distinguish generic/specific files
    @filename = "\"#{filename}\""
    @lineno = lineno
    @pos = 0
    @queue = []
    @backtrace = []
    self
  end

  # calls #feed on the content of the file
  def feed_file(filename)
    feed(File.read(filename), filename)
  end

  Trigraph = {	?= => ?#, ?) => ?], ?! => ?|,
      ?( => ?[, ?' => ?^, ?> => ?},
      ?/ => ?\\,?< => ?{, ?- => ?~ }

  # reads one character from self.text
  # updates self.lineno
  # handles \-continued lines
  def getchar
    @ungetcharpos = @pos
    @ungetcharlineno = @lineno
    c = @text[@pos]
    @pos += 1

    # check trigraph
    #if c == ?? and @text[@pos] == ?? and Trigraph[@text[@pos+1]]
    #	puts "can i has trigraf plox ??#{c.chr} (#@filename:#@lineno)" if $VERBOSE
    #	c = Trigraph[@text[@pos+1]]
    #	@pos += 2
    #end

    # check line continuation
    # TODO portability
    if c == ?\\ and (@text[@pos] == ?\n or (@text[@pos] == ?\r and @text[@pos+1] == ?\n))
      @lineno += 1
      @pos += 1 if @text[@pos] == ?\r
      @pos += 1
      return getchar
    end

    if c == ?\r and @text[@pos] == ?\n
      @pos += 1
      c = ?\n
    end

    # update lineno
    if c == ?\n
      @lineno += 1
    end

    c
  end

  def ungetchar
    @pos = @ungetcharpos
    @lineno = @ungetcharlineno
    nil
  end

  # returns true if no more data is available
  def eos?
    @pos >= @text.length and @queue.empty? and @backtrace.empty?
  end

  # push back a token, will be returned on the next readtok
  # lifo
  def unreadtok(tok)
    @queue << tok if tok
    nil
  end

  # calls readtok_nopp and handles preprocessor directives
  def readtok
    tok = readtok_nopp
    return tok if not @may_preprocess	# shortcut

    if not tok
      # end of file: resume parent
      if not @backtrace.empty?
        raise ParseError, "parse error in #@filename: unmatched #if/#endif" if @backtrace.last.pop != @ifelse_nesting.length
        @filename, @lineno, @text, @pos, @queue = @backtrace.pop
        tok = readtok
      end

    elsif tok.type == :punct and tok.raw == '#' and not tok.expanded_from and @ifelse_nesting.last != :testing
      # backward check for :eol (skip the '#' itself)
      pos = @pos-2
      while pos >= 0		# if reach start of file, proceed
        case @text[pos, 1]
        when "\n"
          pos -= 1 if pos > 0 and @text[pos-1] == ?\r
          return tok if pos > 0 and @text[pos-1] == ?\\	# check if the newline was a line-continuation
          return tok if pos > 2 and @text[pos-3, 3] == '??/'	# trigraph
          break	# proceed
        when /\s/	# beware switch order, this matches "\n" too
        else return tok	# false alarm
        end
        pos -= 1
      end
      pretok = []
      rewind = true
      while ntok = readtok_nopp
        pretok << ntok
        if ntok.type == :space	# nothing
          next
        elsif ntok.type == :string and not ntok.expanded_from
          rewind = false if preprocessor_directive(ntok)
        end
        break
      end
      if rewind
        # false alarm: revert
        pretok.reverse_each { |t| unreadtok t }
      else
        # XXX return :eol ?
        tok = readtok
      end

    elsif tok.type == :string and m = @definition[tok.raw] and not tok.expanded_from.to_a.find { |ef| ef.raw == m.name.raw } and
        ((m.args and margs = Macro.parse_arglist(self)) or not m.args)

      if defined? @traced_macros and tok.backtrace[-2].to_s[0] == ?" and m.name and m.name.backtrace[-2].to_s[0] == ?<
        @traced_macros |= [tok.raw]	# we are in a normal file and expand to an header-defined macro
      end

      m.apply(self, tok, margs).reverse_each { |t| unreadtok t }

      tok = readtok
    end

    tok
  end

  # read and return the next token
  # parses quoted strings (set tok.value) and C/C++ comments (:space/:eol)
  def readtok_nopp
    return @queue.pop unless @queue.empty?

    nbt = []
    @backtrace.each { |bt| nbt << bt[0] << bt[1] }
    tok = Token.new(nbt << @filename << @lineno)

    case c = getchar
    when nil
      return nil
    when ?', ?"
      # read quoted string value
      readtok_nopp_str(tok, c)
    when ?a..?z, ?A..?Z, ?0..?9, ?$, ?_
      tok.type = :string
      raw = tok.raw << c
      while c = getchar
        case c
        when ?a..?z, ?A..?Z, ?0..?9, ?$, ?_
        else break
        end
        raw << c
      end
      ungetchar

    when ?\ , ?\t, ?\r, ?\n, ?\f
      tok.type = ((c == ?\  || c == ?\t) ? :space : :eol)
      raw = tok.raw << c
      while c = getchar
        case c
        when ?\ , ?\t
        when ?\n, ?\f, ?\r; tok.type = :eol
        else break
        end
        raw << c
      end
      ungetchar

    when ?/
      raw = tok.raw << c
      # comment
      case c = getchar
      when ?/
        # till eol
        tok.type = :eol
        raw << c
        while c = getchar
          raw << c
          break if c == ?\n
        end
      when ?*
        tok.type = :space
        raw << c
        seenstar = false
        while c = getchar
          raw << c
          case c
          when ?*; seenstar = true
          when ?/; break if seenstar	# no need to reset seenstar, already false
          else seenstar = false
          end
        end
        raise tok, 'unterminated c++ comment' if not c
      else
        # just a slash
        ungetchar
        tok.type = :punct
      end

    else
      tok.type = :punct
      tok.raw << c
    end

    tok
  end

  # we just read a ' or a ", read until the end of the string
  # tok.value will contain the raw string (with escapes interpreted etc)
  def readtok_nopp_str(tok, delimiter)
    tok.type = :quoted
    tok.raw << delimiter
    tok.value = ''
    tok.value.force_encoding('binary') if tok.value.respond_to?(:force_encoding)
    c = nil
    loop do
      raise tok, 'unterminated string' if not c = getchar
      tok.raw << c
      case c
      when delimiter; break
      when ?\\
        raise tok, 'unterminated escape' if not c = getchar
        tok.raw << c
        tok.value << \
        case c
        when ?n; ?\n
        when ?r; ?\r
        when ?t; ?\t
        when ?a; ?\a
        when ?b; ?\b
        when ?v; ?\v
        when ?f; ?\f
        when ?e; ?\e
        when ?#, ?\\, ?', ?"; c
        when ?\n; ''	# already handled by getchar
        when ?x;
          hex = ''
          while hex.length < 2
            raise tok, 'unterminated escape' if not c = getchar
            case c
            when ?0..?9, ?a..?f, ?A..?F
            else ungetchar; break
            end
            hex << c
            tok.raw << c
          end
          raise tok, 'unterminated escape' if hex.empty?
          hex.hex
        when ?0..?7;
          oct = '' << c
          while oct.length < 3
            raise tok, 'unterminated escape' if not c = getchar
            case c
            when ?0..?7
            else ungetchar; break
            end
            oct << c
            tok.raw << c
          end
          oct.oct
        else c	# raise tok, 'unknown escape sequence'
        end
      when ?\n; ungetchar ; raise tok, 'unterminated string'
      else tok.value << c
      end
    end

    tok
  end


  # defines a simple preprocessor macro (expands to 0 or 1 token)
  # does not check overwriting
  def define(name, value=nil, from=caller.first)
    from =~ /^(.*?):(\d+)/
    btfile, btlineno = $1, $2.to_i
    if not @may_preprocess and @text =~ /#{Regexp.escape name}/
      @may_preprocess = true
    end
    t = Token.new([btfile, btlineno])
    t.type = :string
    t.raw = name.dup
    @definition[name] = Macro.new(t)
    if value.kind_of? ::String and eos?
      feed(value, btfile, btlineno)
      @definition[name].body << readtok until eos?
    elsif value	# XXX won't split multi-token defs..
      t = Token.new([btfile, btlineno])
      t.type = :string
      t.raw = value.to_s
      @definition[name].body << t
    end
  end

  # defines a pp constant if it is not already defined
  def define_weak(name, value=nil, from=caller.first)
    define(name, value, from) if not @definition[name]
  end

  # defines a pp constant so that later #define/#undef will be ignored
  def define_strong(name, value=nil, from=caller.first)
    (@defined_strong ||= []) << name
    define(name, value, from)
  end

  # does not define name, and prevent it from being defined later
  def nodefine_strong(name)
    (@defined_strong ||= []) << name
  end

  # handles #directives
  # returns true if the command is valid
  # second parameter for internal use
  def preprocessor_directive(cmd, ocmd = cmd)
    # read spaces, returns the next token
    # XXX for all commands that may change @ifelse_nesting, ensure last element is :testing to disallow any other preprocessor directive to be run in a bad environment (while looking ahead)
    skipspc = lambda {
      loop do
        tok = readtok_nopp
        break tok if not tok or tok.type != :space
      end
    }

    # XXX do not preprocess tokens when searching for :eol, it will trigger preprocessor directive detection from readtok

    eol = tok = nil
    case cmd.raw
    when 'if'
      case @ifelse_nesting.last
      when :accept, nil
        @ifelse_nesting << :testing
        raise cmd, 'expr expected' if not test = PPExpression.parse(self)
        eol = skipspc[]
        raise eol, 'pp syntax error' if eol and eol.type != :eol
        unreadtok eol
        case test.reduce
        when 0;       @ifelse_nesting[-1] = :discard
        when Integer; @ifelse_nesting[-1] = :accept
        else          @ifelse_nesting[-1] = :discard
        end
      when :discard, :discard_all
        @ifelse_nesting << :discard_all
      end

    when 'ifdef'
      case @ifelse_nesting.last
      when :accept, nil
        @ifelse_nesting << :testing
        raise eol || tok || cmd, 'pp syntax error' if not tok = skipspc[] or tok.type != :string or (eol = skipspc[] and eol.type != :eol)
        unreadtok eol
        @ifelse_nesting[-1] = (@definition[tok.raw] ? :accept : :discard)
      when :discard, :discard_all
        @ifelse_nesting << :discard_all
      end

    when 'ifndef'
      case @ifelse_nesting.last
      when :accept, nil
        @ifelse_nesting << :testing
        raise eol || tok || cmd, 'pp syntax error' if not tok = skipspc[] or tok.type != :string or (eol = skipspc[] and eol.type != :eol)
        unreadtok eol
        @ifelse_nesting[-1] = (@definition[tok.raw] ? :discard : :accept)
      when :discard, :discard_all
        @ifelse_nesting << :discard_all
      end

    when 'elif'
      case @ifelse_nesting.last
      when :accept
        @ifelse_nesting[-1] = :discard_all
      when :discard
        @ifelse_nesting[-1] = :testing
        raise cmd, 'expr expected' if not test = PPExpression.parse(self)
        raise eol, 'pp syntax error' if eol = skipspc[] and eol.type != :eol
        unreadtok eol
        case test.reduce
        when 0;       @ifelse_nesting[-1] = :discard
        when Integer; @ifelse_nesting[-1] = :accept
        else          @ifelse_nesting[-1] = :discard
        end
      when :discard_all
      else raise cmd, 'pp syntax error'
      end

    when 'else'
      @ifelse_nesting << :testing
      @ifelse_nesting.pop
      raise eol || cmd, 'pp syntax error' if @ifelse_nesting.empty? or (eol = skipspc[] and eol.type != :eol)
      unreadtok eol
      case @ifelse_nesting.last
      when :accept
        @ifelse_nesting[-1] = :discard_all
      when :discard
        @ifelse_nesting[-1] = :accept
      when :discard_all
      end

    when 'endif'
      @ifelse_nesting << :testing
      @ifelse_nesting.pop
      raise eol || cmd, 'pp syntax error' if @ifelse_nesting.empty? or (eol = skipspc[] and eol.type != :eol)
      unreadtok eol
      @ifelse_nesting.pop

    when 'define'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

      raise tok || cmd, 'pp syntax error' if not tok = skipspc[] or tok.type != :string
      m = Macro.new(tok)
      valid = m.parse_definition(self)
      if not defined? @defined_strong or not @defined_strong.include? tok.raw
        puts "W: pp: redefinition of #{tok.raw} at #{tok.backtrace_str},\n prev def at #{@definition[tok.raw].name.backtrace_str}" if @definition[tok.raw] and $VERBOSE and @warn_redefinition
        @definition[tok.raw] = m if valid
      end

    when 'undef'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

      raise eol || tok || cmd, 'pp syntax error' if not tok = skipspc[] or tok.type != :string or (eol = skipspc[] and eol.type != :eol)
      if not defined? @defined_strong or not @defined_strong.include? tok.raw
        @definition.delete tok.raw
        unreadtok eol
      end

    when 'include', 'include_next'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

      directive_include(cmd, skipspc)

    when 'error', 'warning'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept
      msg = ''
      while tok = readtok_nopp and tok.type != :eol
        msg << tok.raw
      end
      unreadtok tok
      if cmd.raw == 'warning'
        puts cmd.exception("#warning#{msg}").message if $VERBOSE
      else
        raise cmd, "#error#{msg}"
      end

    when 'line'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

      raise tok || cmd if not tok = skipspc[] or tok.type != :string
      @lineno = Integer(tok.raw) rescue raise(tok, 'bad line number')
      raise eol if eol = skipspc[] and eol.type != :eol
      unreadtok eol

    when 'pragma'
      return if @ifelse_nesting.last and @ifelse_nesting.last != :accept

      directive_pragma(cmd, skipspc)

    else return false
    end

    # skip #ifndef'd parts of the source
    state = 1	# just seen :eol
    while @ifelse_nesting.last == :discard or @ifelse_nesting.last == :discard_all
      begin
        tok = skipspc[]
      rescue ParseError
        # react as gcc -E: <"> unterminated in #if 0 => ok, </*> unterminated => error (the " will fail at eol)
        retry
      end

      if not tok; raise ocmd, 'pp unterminated conditional'
      elsif tok.type == :eol; state = 1
      elsif state == 1 and tok.type == :punct and tok.raw == '#'; state = 2
      elsif state == 2 and tok.type == :string; state = preprocessor_directive(tok, ocmd) ? 1 : 0
      else state = 0
      end
    end

    true
  end

  # handles the '#include' directive, which will insert a new file content in the token stream
  def directive_include(cmd, skipspc)
    raise cmd, 'nested too deeply' if backtrace.length > 200	# gcc

    # allow preprocessing
    nil while tok = readtok and tok.type == :space
    raise tok || cmd, 'pp syntax error' if not tok or (tok.type != :quoted and (tok.type != :punct or tok.raw != '<'))
    if tok.type == :quoted
      ipath = tok.value
      if @filename[0] == ?< or @backtrace.find { |btf, *a| btf[0] == ?< }
        # XXX local include from a std include... (kikoo windows.h !)
        path = nil
        if not @include_search_path.find { |d| ::File.exist?(path = ::File.join(d, ipath)) } ||
          @include_search_path.find { |d| path = file_exist_nocase(::File.join(d, ipath)) } ||
          path = file_exist_nocase(::File.join(::File.dirname(@filename[1..-2]), ipath))
          path = nil
        end
      elsif ipath[0] != ?/
        path = ::File.join(::File.dirname(@filename[1..-2]), ipath) if ipath[0] != ?/
        path = file_exist_nocase(path || ipath) if not ::File.exist?(path || ipath)
      else
        path = ipath
        path = file_exist_nocase(path) if not ::File.exist? path
      end
    else
      # no more preprocessing : allow comments/multiple space/etc
      ipath = ''
      while tok = readtok_nopp and (tok.type != :punct or tok.raw != '>')
        raise cmd, 'syntax error' if tok.type == :eol
        ipath << tok.raw
      end
      raise cmd, 'pp syntax error, unterminated path' if not tok
      if ipath[0] != ?/
        path = nil
        isp = @include_search_path
        if cmd.raw == 'include_next'
          raise self, 'include_next sux' if not idx = isp.find { |d| @filename[1, d.length] == d }
          isp = isp[isp.index(idx)+1..-1]
        end
        if not isp.find { |d| ::File.exist?(path = ::File.join(d, ipath)) } ||
          isp.find { |d| path = file_exist_nocase(::File.join(d, ipath)) }
          path = nil
        end
      end
    end
    eol = nil
    raise eol if eol = skipspc[] and eol.type != :eol
    unreadtok eol
    return if cmd.raw == 'include_next' and not path and not @hooked_include[ipath]	# XXX

    if not @pragma_once[path || ipath]
      @backtrace << [@filename, @lineno, @text, @pos, @queue, @ifelse_nesting.length]

      # gcc-style autodetect
      # XXX the headers we already parsed may have needed a prepare_gcc...
      # maybe restart parsing ?
      if ipath == 'stddef.h' and not path and not @hooked_include[ipath]
        tk = tok.dup
        tk.raw = 'prepare_gcc'
        @pragma_callback[tk]
        if @hooked_include[ipath]
          puts "metasm pp: autodetected gcc-style headers" if $VERBOSE
        end
      end

      if @hooked_include[ipath]
        path = '<hooked>/'+ipath
        puts "metasm preprocessor: including #{path}" if $DEBUG
        @text = @hooked_include[ipath]
      else
        puts "metasm preprocessor: including #{path}" if $DEBUG
        raise cmd, "No such file or directory #{ipath.inspect}" if not path or not ::File.exist? path
        raise cmd, 'filename too long' if path.length > 4096		# gcc
        @text = ::File.read(path)
      end

      # @filename[-1] used in trace_macros to distinguish generic/specific files
      if tok.type == :quoted
        @filename = '"' + path + '"'
      else
        @filename = '<' + path + '>'
      end
      @lineno = 1
      @pos = 0
      @queue = []
    else
      puts "metasm preprocessor: not reincluding #{path} (pragma once)" if $DEBUG
    end
  end

  # checks if a file exists
  # search for case-insensitive variants of the path
  # returns the match if found, or nil
  def file_exist_nocase(name)
    componants = name.tr('\\', '/').split('/')
    if componants[0] == ''
      ret = '/'
      componants.shift
    else
      ret = './'
    end
    componants.each { |cp|
      return if not ccp = Dir.entries(ret).find { |ccp_| ccp_.downcase == cp.downcase }
      ret = File.join(ret, ccp)
    }
    ret
  end

  # handles a '#pragma' directive in the preprocessor source
  # here we handle:
  # 'once': do not re-#include this file
  # 'no_warn_redefinition': macro redefinition warning
  # 'include_dir' / 'include_path': insert directories in the #include <xx> search path (this new dir will be searched first)
  # 'push_macro' / 'pop_macro': allows temporary redifinition of a macro with later restoration
  # other directives are forwarded to @pragma_callback
  def directive_pragma(cmd, skipspc)
    nil while tok = readtok and tok.type == :space
    raise tok || cmd if not tok or tok.type != :string

    case tok.raw
    when 'once'
      @pragma_once[@filename[1..-2]] = true
    when 'no_warn_redefinition'
      @warn_redefinition = false
    when 'include_dir', 'include_path'
      nil while dir = readtok and dir.type == :space
      raise cmd, 'qstring expected' if not dir or dir.type != :quoted
      dir = ::File.expand_path dir.value
      raise cmd, "invalid path #{dir.inspect}" if not ::File.directory? dir
      @include_search_path.unshift dir

    when 'push_macro', 'pop_macro'
      @pragma_macro_stack ||= []
      nil while lp = readtok and lp.type == :space
      nil while m = readtok and m.type == :space
      nil while rp = readtok and rp.type == :space
      raise cmd if not rp or lp.type != :punct or rp.type != :punct or lp.raw != '(' or rp.raw != ')' or m.type != :quoted
      if tok.raw == 'push_macro'
        @pragma_macro_stack << @definition[m.value]
      else
        raise cmd, "macro stack empty" if @pragma_macro_stack.empty?
        if mbody = @pragma_macro_stack.pop	# push undefined macro allowed
          @definition[m.value] = mbody
        else
          @definition.delete m.value
        end
      end
    else
      @pragma_callback[tok]
    end

    eol = nil
    raise eol, 'eol expected' if eol = skipspc[] and eol.type != :eol
    unreadtok eol
  end

  # parses a preprocessor expression (similar to Expression, + handles "defined(foo)"), returns an Expression
  class PPExpression
  class << self
    # reads an operator from the lexer, returns the corresponding symbol or nil
    def readop(lexer)
      if not tok = lexer.readtok or tok.type != :punct
        lexer.unreadtok tok
        return
      end

      op = tok
      case op.raw
      # may be followed by itself or '='
      when '>', '<'
        if ntok = lexer.readtok and ntok.type == :punct and (ntok.raw == op.raw or ntok.raw == '=')
          op = op.dup
          op.raw << ntok.raw
        else
          lexer.unreadtok ntok
        end
      # may be followed by itself
      when '|', '&'
        if ntok = lexer.readtok and ntok.type == :punct and ntok.raw == op.raw
          op = op.dup
          op.raw << ntok.raw
        else
          lexer.unreadtok ntok
        end
      # must be followed by '='
      when '!', '='
        if not ntok = lexer.readtok or ntok.type != :punct and ntok.raw != '='
          lexer.unreadtok ntok
          lexer.unreadtok tok
          return
        end
        op = op.dup
        op.raw << ntok.raw
      # ok
      when '^', '+', '-', '*', '/', '%', '>>', '<<', '>=', '<=', '||', '&&', '!=', '=='
      # unknown
      else
        lexer.unreadtok tok
        return
      end
      op.value = op.raw.to_sym
      op
    end

    # handles floats and "defined" keyword
    def parse_intfloat(lexer, tok)
      if tok.type == :string and tok.raw == 'defined'
        nil while ntok = lexer.readtok_nopp and ntok.type == :space
        raise tok if not ntok
        if ntok.type == :punct and ntok.raw == '('
          nil while ntok = lexer.readtok_nopp and ntok.type == :space
          nil while rtok = lexer.readtok_nopp and rtok.type == :space
          raise tok if not rtok or rtok.type != :punct or rtok.raw != ')'
        end
        raise tok if not ntok or ntok.type != :string
        tok.value = lexer.definition[ntok.raw] ? 1 : 0
        return
      elsif tok.type == :string and tok.raw == 'L'
        ntok = lexer.readtok_nopp
        if ntok.type == :quoted and ntok.raw[0] == ?'
          tok.raw << ntok.raw
          tok.value = (ntok.value + "\0\0").unpack('v')	# XXX endianness
        else
          lexer.unreadtok ntok
        end
      end

      Expression.parse_num_value(lexer, tok)
    end

    # returns the next value from lexer (parenthesised expression, immediate, variable, unary operators)
    # single-line only, and does not handle multibyte char string
    def parse_value(lexer)
      nil while tok = lexer.readtok and tok.type == :space
      return if not tok
      case tok.type
      when :string
        parse_intfloat(lexer, tok)
        val = tok.value || tok.raw
      when :quoted
        if tok.raw[0] != ?' or tok.value.length > 1	# allow single-char
          lexer.unreadtok tok
          return
        end
        val = tok.value[0]
      when :punct
        case tok.raw
        when '('
          val = parse(lexer)
          nil while ntok = lexer.readtok and ntok.type == :space
          raise tok, "')' expected after #{val.inspect} got #{ntok.inspect}" if not ntok or ntok.type != :punct or ntok.raw != ')'
        when '!', '+', '-', '~'
          nil while ntok = lexer.readtok and ntok.type == :space
          lexer.unreadtok ntok
          raise tok, 'need expression after unary operator' if not val = parse_value(lexer)
          val = Expression[tok.raw.to_sym, val]
        when '.'
          parse_intfloat(lexer, tok)
          if not tok.value
            lexer.unreadtok tok
            return
          end
          val = tok.value
        else
          lexer.unreadtok tok
          return
        end
      else
        lexer.unreadtok tok
        return
      end
      nil while tok = lexer.readtok and tok.type == :space
      lexer.unreadtok tok
      val
    end

    def parse(lexer)
      opstack = []
      stack = []

      return if not e = parse_value(lexer)

      stack << e

      while op = readop(lexer)
        nil while ntok = lexer.readtok and ntok.type == :space
        lexer.unreadtok ntok
        until opstack.empty? or Expression::OP_PRIO[op.value][opstack.last]
          stack << Expression.new(opstack.pop, stack.pop, stack.pop)
        end

        opstack << op.value

        raise op, 'need rhs' if not e = parse_value(lexer)

        stack << e
      end

      until opstack.empty?
        stack << Expression.new(opstack.pop, stack.pop, stack.pop)
      end

      Expression[stack.first]
    end
  end
  end
end
end
