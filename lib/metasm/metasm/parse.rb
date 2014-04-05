#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/preprocessor'

module Metasm
class Data
  # keywords for data definition (used to recognize label names)
  DataSpec = %w[db dw dd dq]
end

class CPU
  # parses prefix/name/arguments
  # returns an +Instruction+ or raise a ParseError
  # if the parameter is a String, a custom AsmPP is built - XXX it will not be able to create labels (eg jmp 1b / jmp $)
  def parse_instruction(lexer)
    lexer = new_asmprepro(lexer) if lexer.kind_of? String

    i = Instruction.new self

    # find prefixes, break on opcode name
    while tok = lexer.readtok and parse_prefix(i, tok.raw)
      lexer.skip_space_eol
    end
    return if not tok

    # allow '.' in opcode name
    tok = tok.dup
    while ntok = lexer.nexttok and ntok.type == :punct and ntok.raw == '.'
      tok.raw << lexer.readtok.raw
      ntok = lexer.readtok
      raise tok, 'invalid opcode name' if not ntok or ntok.type != :string
      tok.raw << ntok.raw
    end

    raise tok, 'invalid opcode' if not opcode_list_byname[tok.raw]

    i.opname = tok.raw
    i.backtrace = tok.backtrace
    lexer.skip_space

    # find arguments list
    loop do
      break if not ntok = lexer.nexttok
      break if i.args.empty? and opcode_list_byname[ntok.raw] and opcode_list_byname[i.opname].find { |op| op.args.empty? }
      break if not arg = parse_argument(lexer)
      i.args << arg
      lexer.skip_space
      break if not ntok = lexer.nexttok or ntok.type != :punct or ntok.raw != ','
      lexer.readtok
      lexer.skip_space_eol
    end

    if not parse_instruction_checkproto(i)
      raise tok, "invalid opcode arguments #{i.to_s.inspect}, allowed : #{opcode_list_byname[i.opname].to_a.map { |o| o.args }.inspect}"
    end
    parse_instruction_fixup(i)

    i
  end

  def parse_instruction_checkproto(i)
    opcode_list_byname[i.opname].to_a.find { |o|
      o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
    }
  end

  # called after the instruction is fully parsed
  def parse_instruction_fixup(i)
  end

  # return false if not a prefix
  def parse_prefix(i, word)
  end

  # returns a parsed argument
  # add your own arguments parser here (registers, memory references..)
  def parse_argument(lexer)
    Expression.parse(lexer)
  end

  # handles .instructions
  # XXX handle HLA here ?
  def parse_parser_instruction(lexer, instr)
    raise instr, 'unknown parser instruction'
  end
end

# asm-specific preprocessor
# handles asm arguments (; ... eol)
# asm macros (name macro args\nbody endm, name equ val)
# initializes token.value (reads integers in hex etc)
# merges consecutive space/eol
class AsmPreprocessor < Preprocessor
  # an assembler macro, similar to preprocessor macro
  # handles local labels
  class Macro
    attr_accessor :name, :args, :body, :labels

    def initialize(name)
      @name = name
      @args, @body, @labels = [], [], []
    end

    # returns the array of token resulting from the application of the macro
    # parses arguments if needed, handles macro-local labels
    def apply(macro, lexer, program)
      args = Preprocessor::Macro.parse_arglist(lexer).to_a
      raise @name, 'invalid argument count' if args.length != @args.length

      labels = @labels.inject({}) { |h, l| h.update l => program.new_label(l) }
      args = @args.zip(args).inject({}) { |h, (fa, a)| h.update fa.raw => a }

      # apply macro
      @body.map { |t|
        t = t.dup
        t.backtrace += macro.backtrace[-2..-1] if not macro.backtrace.empty?
        if labels[t.raw]
          t.raw = labels[t.raw]
          t
        elsif args[t.raw]
          # XXX update toks backtrace ?
          args[t.raw]
        else
          t
        end
      }.flatten
    end

    # parses the argument list and the body from lexer
    # recognize the local labels
    # XXX add eax,
    #      toto db 42	; zomg h4x
    def parse_definition(lexer)
      lexer.skip_space
      while tok = lexer.nexttok and tok.type != :eol
        # no preprocess argument list
        raise @name, 'invalid arg definition' if not tok = lexer.readtok or tok.type != :string
        @args << tok
        lexer.skip_space
        raise @name, 'invalid arg separator' if not tok = lexer.readtok or ((tok.type != :punct or tok.raw != ',') and tok.type != :eol)
        break if tok.type == :eol
        lexer.skip_space
      end

      lexer.skip_space_eol
      while tok = lexer.readtok and (tok.type != :string or tok.raw != 'endm')
        @body << tok
        if @body[-2] and @body[-2].type == :string and @body[-1].raw == ':' and (not @body[-3] or @body[-3].type == :eol) and @body[-2].raw !~ /^[1-9][0-9]*$/
          @labels << @body[-2].raw
        elsif @body[-3] and @body[-3].type == :string and @body[-2].type == :space and Data::DataSpec.include?(@body[-1].raw) and (not @body[-4] or @body[-4].type == :eol)
          @labels << @body[-3].raw
        end
      end
    end
  end

  class Preprocessor::Token
    # token already preprocessed for macro def/expansion
    attr_accessor :alreadyapp
  end

  # the program (used to create new label names)
  attr_accessor :program
  # hash macro name => Macro
  attr_accessor :macro
  attr_accessor :may_apreprocess

  def initialize(text='', program=nil)
    @program = program
    @may_apreprocess = false
    @macro = {}
    super(text)
  end

  def skip_space_eol
    readtok while t = nexttok and (t.type == :space or t.type == :eol)
  end

  def skip_space
    readtok while t = nexttok and t.type == :space
  end

  def nexttok
    t = readtok
    unreadtok t
    t
  end

  def feed!(*a)
    super(*a)
    if not @may_apreprocess and (@text =~ / (macro|equ) / or not @macro.empty?)
      @may_apreprocess = true
    end
    self
  end

  # reads a token, handles macros/comments/etc
  def readtok
    tok = super()
    return tok if not tok or tok.alreadyapp

    # handle ; comments
    if tok.type == :punct and tok.raw[0] == ?;
      tok.type = :eol
      begin
        tok = tok.dup
        while ntok = super() and ntok.type != :eol
          tok.raw << ntok.raw
        end
        tok.raw << ntok.raw if ntok
      rescue ParseError
        # unterminated string
      end
    end

    # handle macros
    if @may_apreprocess and tok.type == :string
      if @macro[tok.raw]
        @macro[tok.raw].apply(tok, self, @program).reverse_each { |t| unreadtok t }
        tok = readtok
      else
        if ntok = super() and ntok.type == :space and nntok = super() and nntok.type == :string and (nntok.raw == 'macro' or nntok.raw == 'equ')
          puts "W: asm: redefinition of macro #{tok.raw} at #{tok.backtrace_str}, previous definition at #{@macro[tok.raw].name.backtrace_str}" if @macro[tok.raw]
          m = Macro.new tok
          # XXX this allows nested macro definition..
          if nntok.raw == 'macro'
            m.parse_definition self
          else
            # equ
            raise nntok if not etok = readtok
            unreadtok etok
            raise nntok if not v = Expression.parse(self)
            etok = etok.dup
            etok.type = :string
            etok.value = v
            etok.raw = v.to_s
            m.body << etok
          end
          @macro[tok.raw] = m
          tok = readtok
        else
          unreadtok nntok
          unreadtok ntok
        end
      end
    end

    tok.alreadyapp = true if tok
    tok
  end
end

class ExeFormat
  # setup self.cursource here
  def parse_init
    @locallabels_bkw ||= {}
    @locallabels_fwd ||= {}
  end

  # hash mapping local anonymous label number => unique name
  # defined only while parsing
  # usage:
  #   jmp 1f
  #  1:
  #   jmp 1f
  #   jmp 1b
  #  1:
  # defined in #parse, replaced in use by Expression#parse
  # no macro-scope (macro are gsub-like, and no special handling for those labels is done)
  def locallabels_bkw(id)
    @locallabels_bkw[id]
  end
  def locallabels_fwd(id)
    @locallabels_fwd[id] ||= new_label("local_#{id}")
  end

  # parses an asm source file to an array of Instruction/Data/Align/Offset/Padding
  def parse(text, file='<ruby>', lineno=0)
    parse_init
    @lexer ||= cpu.new_asmprepro('', self)
    @lexer.feed text, file, lineno
    lasteol = true

    while not @lexer.eos?
      tok = @lexer.readtok
      next if not tok
      case tok.type
      when :space
      when :eol
        lasteol = true
      when :punct
        case tok.raw
        when '.'
          tok = tok.dup
          while ntok = @lexer.nexttok and ((ntok.type == :string) or (ntok.type == :punct and ntok.raw == '.'))
            tok.raw << @lexer.readtok.raw
          end
          parse_parser_instruction tok
        else raise tok, 'syntax error'
        end
        lasteol = false
      when :string
        ntok = nntok = nil
        if lasteol and ((ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ':') or
            (ntok and ntok.type == :space and nntok = @lexer.nexttok and nntok.type == :string and Data::DataSpec.include?(nntok.raw)))
          if tok.raw =~ /^[1-9][0-9]*$/
            # handle anonymous local labels
            lname = @locallabels_bkw[tok.raw] = @locallabels_fwd.delete(tok.raw) || new_label('local_'+tok.raw)
          else
            lname = tok.raw
            raise tok, "invalid label name: #{lname.inspect} is reserved" if @cpu.check_reserved_name(lname)
            raise tok, "label redefinition" if new_label(lname) != lname
          end
          l = Label.new(lname)
          l.backtrace = tok.backtrace
          @cursource << l
          lasteol = false
        else
          lasteol = false
          @lexer.unreadtok ntok
          @lexer.unreadtok tok
          if Data::DataSpec.include?(tok.raw)
            @cursource << parse_data
          else
            @cursource << @cpu.parse_instruction(@lexer)
          end
          if lname = @locallabels_fwd.delete('endinstr')
            l = Label.new(lname)
            l.backtrace = tok.backtrace
            @cursource << l
          end
        end
      else
        raise tok, 'syntax error'
      end
    end

    puts "Undefined forward reference to anonymous labels #{@locallabels_fwd.keys.inspect}" if $VERBOSE and not @locallabels_fwd.empty?

    self
  end

  # create a new label from base, parse it (incl optionnal additionnal src)
  # returns the new label name
  def parse_new_label(base='', src=nil)
    parse_init
    label = new_label(base)
    @cursource << Label.new(label)
    parse src
    label
  end

  # handles special directives (alignment, changing section, ...)
  # special directives start with a dot
  def parse_parser_instruction(tok)
    case tok.raw.downcase
    when '.align'
      e = Expression.parse(@lexer).reduce
      raise self, 'need immediate alignment size' unless e.kind_of? ::Integer
      @lexer.skip_space
      if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
        @lexer.skip_space_eol
        # allow single byte value or full data statement
        if not ntok = @lexer.readtok or not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
          @lexer.unreadtok ntok
          type = 'db'
        else
          type = ntok.raw
        end
        fillwith = parse_data_data type
      else
        @lexer.unreadtok ntok
      end
      raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
      @cursource << Align.new(e, fillwith, tok.backtrace)

    when '.pad'
      @lexer.skip_space
      if ntok = @lexer.readtok and ntok.type != :eol
        # allow single byte value or full data statement
        if not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
          @lexer.unreadtok ntok
          type = 'db'
        else
          type = ntok.raw
        end
        fillwith = parse_data_data(type)
      else
        @lexer.unreadtok ntok
      end
      raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
      @cursource << Padding.new(fillwith, tok.backtrace)

    when '.offset'
      e = Expression.parse(@lexer)
      raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
      @cursource << Offset.new(e, tok.backtrace)

    when '.padto'
      e = Expression.parse(@lexer)
      @lexer.skip_space
      if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
        @lexer.skip_space
        # allow single byte value or full data statement
        if not ntok = @lexer.readtok or not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
          @lexer.unreadtok ntok
          type = 'db'
        else
          type = ntok.raw
        end
        fillwith = parse_data_data type
      else
        @lexer.unreadtok ntok
      end
      raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
      @cursource << Padding.new(fillwith, tok.backtrace) << Offset.new(e, tok.backtrace)

    else
      @cpu.parse_parser_instruction(self, tok)
    end
  end

  def parse_data
    raise ParseError, 'internal error' if not tok = @lexer.readtok
    raise tok, 'invalid data type' if tok.type != :string or not Data::DataSpec.include?(tok.raw)
    type = tok.raw
    @lexer.skip_space_eol
    arr = []
    loop do
      arr << parse_data_data(type)
      @lexer.skip_space
      if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
        @lexer.skip_space_eol
      else
        @lexer.unreadtok ntok
        break
      end
    end
    Data.new(type, arr, 1, tok.backtrace)
  end

  def parse_data_data(type)
    raise ParseError, 'need data content' if not tok = @lexer.readtok
    if tok.type == :punct and tok.raw == '?'
      Data.new type, :uninitialized, 1, tok.backtrace
    elsif tok.type == :quoted
      Data.new type, tok.value, 1, tok.backtrace
    else
      @lexer.unreadtok tok
      raise tok, 'invalid data' if not i = Expression.parse(@lexer)
      @lexer.skip_space
      if ntok = @lexer.readtok and ntok.type == :string and ntok.raw.downcase == 'dup'
        raise ntok, 'need immediate count expression' unless (count = i.reduce).kind_of? ::Integer
        @lexer.skip_space
        raise ntok, 'syntax error, ( expected' if not ntok = @lexer.readtok or ntok.type != :punct or ntok.raw != '('
        content = []
        loop do
          content << parse_data_data(type)
          @lexer.skip_space
          if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
            @lexer.skip_space_eol
          else
            @lexer.unreadtok ntok
            break
          end
        end
        raise ntok, 'syntax error, ) expected' if not ntok = @lexer.readtok or ntok.type != :punct or ntok.raw != ')'
        Data.new type, content, count, tok.backtrace
      else
        @lexer.unreadtok ntok
        Data.new type, i, 1, tok.backtrace
      end
    end
  end
end

class Expression
    # key = operator, value = hash regrouping operators of lower precedence
    OP_PRIO = [[:'||'], [:'&&'], [:|], [:^], [:&], [:'==', :'!='],
      [:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-], [:*, :/, :%]
    ].inject({}) { |h, oplist|
      lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
      oplist.each { |op| h[op] = lessprio }
      h }


  class << self
    # reads an operator from the lexer, returns the corresponding symbol or nil
    def readop(lexer)
      if not tok = lexer.readtok or tok.type != :punct
        lexer.unreadtok tok
        return
      end

      if tok.value
        if OP_PRIO[tok.value]
          return tok
        else
          lexer.unreadtok tok
          return
        end
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
      when '^', '+', '-', '*', '/', '%'
      # unknown
      else
        lexer.unreadtok tok
        return
      end
      op.value = op.raw.to_sym
      op
    end

    # parses floats/hex into tok.value, returns nothing
    # does not parse unary operators (-/+/~)
    def parse_num_value(lexer, tok)
      if not tok.value and tok.raw =~ /^[a-f][0-9a-f]*h$/i
        # warn on variable name like ffffh
        puts "W: Parser: you may want to add a leading 0 to #{tok.raw.inspect} at #{tok.backtrace[-2]}:#{tok.backtrace[-1]}" if $VERBOSE
      end

      return if tok.value
      return if tok.raw[0] != ?. and !(?0..?9).include? tok.raw[0]

      case tr = tok.raw.downcase
      when /^0b([01][01_]*)$/, /^([01][01_]*)b$/
        tok.value = $1.to_i(2)

      when /^(0[0-7][0-7_]*)$/
        tok.value = $1.to_i(8)

      when /^([0-9][a-f0-9_]*)h$/
        tok.value = $1.to_i(16)

      when /^0x([a-f0-9][a-f0-9_]*)(u?l?l?|l?l?u?|p([0-9][0-9_]*[fl]?)?)$/, '0x'
        tok.value = $1.to_i(16) if $1
        ntok = lexer.readtok

        # check for C99 hex float
        if not tr.include? 'p' and ntok and ntok.type == :punct and ntok.raw == '.'
          if not nntok = lexer.readtok or nntok.type != :string
            lexer.unreadtok nntok
            lexer.unreadtok ntok
            return
          end
          # read all pre-mantissa
          tok.raw << ntok.raw
          ntok = nntok
          tok.raw << ntok.raw if ntok
          raise tok, 'invalid hex float' if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9a-f_]*p([0-9][0-9_]*[fl]?)?$/i
          raise tok, 'invalid hex float' if tok.raw.delete('_').downcase[0,4] == '0x.p'	# no digits
          ntok = lexer.readtok
        end

        if not tok.raw.downcase.include? 'p'
          # standard hex
          lexer.unreadtok ntok
        else
          if tok.raw.downcase[-1] == ?p
            # read signed mantissa
            tok.raw << ntok.raw if ntok
            raise tok, 'invalid hex float' if not ntok or ntok.type == :punct or (ntok.raw != '+' and ntok.raw != '-')
            ntok = lexer.readtok
            tok.raw << ntok.raw if ntok
            raise tok, 'invalid hex float' if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9][0-9_]*[fl]?$/i
          end

          raise tok, 'internal error' if not tok.raw.delete('_').downcase =~ /^0x([0-9a-f]*)(?:\.([0-9a-f]*))?p([+-]?[0-9]+)[fl]?$/
          b1, b2, b3 = $1.to_i(16), $2, $3.to_i
          b2 = b2.to_i(16) if b2
          tok.value = b1.to_f
          # tok.value += 1/b2.to_f # TODO
          puts "W: unhandled hex float #{tok.raw}" if $VERBOSE and b2 and b2 != 0
          tok.value *= 2**b3
          puts "hex float: #{tok.raw} => #{tok.value}" if $DEBUG
        end

      when /^([0-9][0-9_]*)(u?l?l?|l?l?u?|e([0-9][0-9_]*[fl]?)?)$/, '.'
        tok.value = $1.to_i if $1
        ntok = lexer.readtok
        if tok.raw == '.' and (not ntok or ntok.type != :string)
          lexer.unreadtok ntok
          return
        end

        if not tr.include? 'e' and tr != '.' and ntok and ntok.type == :punct and ntok.raw == '.'
          if not nntok = lexer.readtok or nntok.type != :string
            lexer.unreadtok nntok
            lexer.unreadtok ntok
            return
          end
          # read upto '.'
          tok.raw << ntok.raw
          ntok = nntok
        end

        if not tok.raw.downcase.include? 'e' and tok.raw[-1] == ?.
          # read fractional part
          tok.raw << ntok.raw if ntok
          raise tok, 'bad float' if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9_]*(e[0-9_]*)?[fl]?$/i
          ntok = lexer.readtok
        end

        if tok.raw.downcase[-1] == ?e
          # read signed exponent
          tok.raw << ntok.raw if ntok
          raise tok, 'bad float' if not ntok or ntok.type != :punct or (ntok.raw != '+' and ntok.raw != '-')
          ntok = lexer.readtok
          tok.raw << ntok.raw if ntok
          raise tok, 'bad float' if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9][0-9_]*[fl]?$/i
          ntok = lexer.readtok
        end

        lexer.unreadtok ntok

        if tok.raw.delete('_').downcase =~ /^(?:(?:[0-9]+\.[0-9]*|\.[0-9]+)(?:e[+-]?[0-9]+)?|[0-9]+e[+-]?[0-9]+)[fl]?$/i
          tok.value = tok.raw.to_f
        else
          raise tok, 'internal error' if tok.raw =~ /[e.]/i
        end

      else raise tok, 'invalid numeric constant'
      end
    end

    # parses an integer/a float, sets its tok.value, consumes&aggregate necessary following tokens (point, mantissa..)
    # handles $/$$ special asm label name
    # XXX for binary, use _ delimiter or 0b prefix, or start with 0 : 1b may conflict with backward local anonymous label reference
    def parse_intfloat(lexer, tok)
      if not tok.value and tok.raw == '$'
        l = lexer.program.cursource.last
        if not l.kind_of? Label
          l = Label.new(lexer.program.new_label('instr_start'))
          l.backtrace = tok.backtrace
          lexer.program.cursource << l
        end
        tok.value = l.name
      elsif not tok.value and tok.raw == '$$'
        l = lexer.program.cursource.first
        if not l.kind_of? Label
          l = Label.new(lexer.program.new_label('section_start'))
          l.backtrace = tok.backtrace
          lexer.program.cursource.unshift l
        end
        tok.value = l.name
      elsif not tok.value and tok.raw == '$_'
        tok.value = lexer.program.locallabels_fwd('endinstr')
      elsif not tok.value and tok.raw =~ /^([1-9][0-9]*)([fb])$/
        case $2
        when 'b'; tok.value = lexer.program.locallabels_bkw($1)	# may fallback to binary parser
        when 'f'; tok.value = lexer.program.locallabels_fwd($1)
        end
      end

      parse_num_value(lexer, tok)
    end

    # returns the next value from lexer (parenthesised expression, immediate, variable, unary operators)
    def parse_value(lexer)
      nil while tok = lexer.readtok and tok.type == :space
      return if not tok
      case tok.type
      when :string
        # ignores the 'offset' word if followed by a string
        if not tok.value and tok.raw.downcase == 'offset'
          nil while ntok = lexer.readtok and ntok.type == :space
          if ntok.type == :string; tok = ntok
          else lexer.unreadtok ntok
          end
        end
        parse_intfloat(lexer, tok)
        val = tok.value || tok.raw
      when :quoted
        if tok.raw[0] != ?'
          lexer.unreadtok tok
          return
        end
        s = tok.value || tok.raw[1..-2]	# raise tok, 'need ppcessing !'
        s = s.reverse if lexer.respond_to? :program and lexer.program and lexer.program.cpu and lexer.program.cpu.endianness == :little
        val = s.unpack('C*').inject(0) { |sum, c| (sum << 8) | c }
      when :punct
        case tok.raw
        when '('
          nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
          lexer.unreadtok ntok
          val = parse(lexer)
          nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
          raise tok, "syntax error, no ) found after #{val.inspect}, got #{ntok.inspect}" if not ntok or ntok.type != :punct or ntok.raw != ')'
        when '!', '+', '-', '~'
          nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
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

    # for boolean operators, true is 1 (or anything != 0), false is 0
    def parse(lexer)
      opstack = []
      stack = []

      return if not e = parse_value(lexer)

      stack << e

      while op = readop(lexer)
        nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
        lexer.unreadtok ntok
        until opstack.empty? or OP_PRIO[op.value][opstack.last]
          stack << new(opstack.pop, stack.pop, stack.pop)
        end

        opstack << op.value

        raise op, 'need rhs' if not e = parse_value(lexer)

        stack << e
      end

      until opstack.empty?
        stack << new(opstack.pop, stack.pop, stack.pop)
      end

      Expression[stack.first]
    end

    # parse an expression in a string
    # updates the string to point after the parsed expression
    def parse_string!(str, &b)
      pp = Preprocessor.new(str)

      e = parse(pp, &b)

      # update arg
      len = pp.pos
      pp.queue.each { |t| len -= t.raw.length }
      str[0, len] = ''

      e
    end

    # parse an expression in a string
    def parse_string(str, &b)
      parse(Preprocessor.new(str), &b)
    end
  end
end

# an Expression whose ::parser handles indirection (byte ptr [foobar])
class IndExpression < Expression
  class << self
    def parse_value(lexer)
      sz = nil
      ptr = nil
      loop do
        nil while tok = lexer.readtok and tok.type == :space
        return if not tok
        case tok.raw
        when 'qword'; sz=8
        when 'dword'; sz=4
        when 'word'; sz=2
        when 'byte'; sz=1
        when 'ptr'
        when '['
          ptr = parse(lexer)
          nil while tok = lexer.readtok and tok.type == :space
          raise tok || lexer, '] expected' if tok.raw != ']'
          break
        when '*'
          ptr = parse_value(lexer)
          break
        when ':'	# symbols, eg ':eax'
          n = lexer.readtok
          nil while tok = lexer.readtok and tok.type == :space
          lexer.unreadtok tok
          return n.raw.to_sym
        else
          lexer.unreadtok tok
          break
        end
      end
      raise lexer, 'invalid indirection' if sz and not ptr
      if ptr; Indirection[ptr, sz]	# if sz is nil, default cpu pointersz is set in resolve_expr
      else super(lexer)
      end
    end

    def parse(*a, &b)
      # custom decimal converter
      @parse_cb = b if b
      e = super(*a)
      @parse_cb = nil if b
      e
    end

    # callback used to customize the parsing of /^([0-9]+)$/ tokens
    # implicitely set by parse(expr) { cb }
    # allows eg parsing '40000' as 0x40000 when relevant
    attr_accessor :parse_cb

    def parse_intfloat(lexer, tok)
      case tok.raw
      when /^([0-9]+)$/; tok.value = parse_cb ? @parse_cb[$1] : $1.to_i
      when /^0x([0-9a-f]+)$/i, /^([0-9a-f]+)h$/i; tok.value = $1.to_i(16)
      when /^0b([01]+)$/i; tok.value = $1.to_i(2)
      end
    end

    def readop(lexer)
      if t0 = lexer.readtok and t0.raw == '-' and t1 = lexer.readtok and t1.raw == '>'
        op = t0.dup
        op.raw << t1.raw
        op.value = op.raw.to_sym
        op
      else
        lexer.unreadtok t1
        lexer.unreadtok t0
        super(lexer)
      end
    end

    def new(op, r, l)
      return Indirection[[l, :+, r], nil] if op == :'->'
      super(op, r, l)
    end
  end
end
end
