#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


module Metasm

VERSION = 0x0001	# major major minor minor

# superclass for all metasm exceptions
class Exception < RuntimeError ; end
# parse error
class ParseError < Exception ; end
# invalid exeformat signature
class InvalidExeFormat < Exception ; end
# cannot honor .offset specification, reloc fixup overflow
class EncodeError < Exception ; end

# holds context of a processor
# endianness, current mode, opcode list...
class CPU
  attr_accessor :valid_args, :valid_props, :fields_mask
  attr_accessor :endianness, :size
  attr_accessor :generate_PIC

  def opcode_list
    @opcode_list ||= init_opcode_list
  end
  def opcode_list=(l) @opcode_list = l end

  def initialize
    @fields_mask = {}
    @fields_shift= {}
    @valid_args  = {}
    @valid_props = { :setip => true, :saveip => true, :stopexec => true }
    @generate_PIC = true
  end

  # returns a hash opcode_name => array of opcodes with this name
  def opcode_list_byname
    @opcode_list_byname ||= opcode_list.inject({}) { |h, o| (h[o.name] ||= []) << o ; h }
  end

  # sets up the C parser : standard macro definitions, type model (size of int etc)
  def tune_cparser(cp)
    case @size
    when 64; cp.lp64
    when 32; cp.ilp32
    when 16; cp.ilp16
    end
    cp.endianness = @endianness
    cp.lexer.define_weak('_STDC', 1)
    # TODO gcc -dM -E - </dev/null
    tune_prepro(cp.lexer)
  end

  def tune_prepro(pp)
    # TODO pp.define('BIGENDIAN')
  end

  # return a new AsmPreprocessor
  def new_asmprepro(str='', exe=nil)
    pp = AsmPreprocessor.new(str, exe)
    tune_prepro(pp)
    exe.tune_prepro(pp) if exe
    pp
  end

  # returns a new & tuned C::Parser
  def new_cparser
    C::Parser.new(self)
  end

  # returns a new C::Compiler
  def new_ccompiler(parser, exe=ExeFormat.new)
    exe.cpu = self if not exe.instance_variable_get("@cpu")
    C::Compiler.new(parser, exe)
  end

  def shortname
    self.class.name.sub(/.*::/, '').downcase
  end

  # some userinterface wants to hilight a word, return a regexp
  # useful for register aliases
  # the regexp will be enclosed in \b and should not contain captures
  def gui_hilight_word_regexp(word)
    Regexp.escape(word)
  end

  # returns true if the name is invalid as a label name (eg register name)
  def check_reserved_name(name)
  end
end

# generic CPU, with no instructions, just size/endianness
class UnknownCPU < CPU
  def initialize(size, endianness)
    super()
    @size, @endianness = size, endianness
  end
end

# a cpu instruction 'formal' description
class Opcode
  # the name of the instruction
  attr_accessor :name
  # formal description of arguments (array of cpu-specific symbols)
  attr_accessor :args
  # binary encoding of the opcode (integer for risc, array of bytes for cisc)
  attr_accessor :bin
  # list of bit fields in the binary encoding
  # hash position => field
  # position is bit shift for risc, [byte index, bit shift] for risc
  # field is cpu-specific
  attr_accessor :fields
  # hash of opcode generic properties/restrictions (mostly property => true/false)
  attr_accessor :props
  # binary mask for decoding
  attr_accessor :bin_mask

  def initialize(name, bin=nil)
    @name = name
    @bin = bin
    @args = []
    @fields = {}
    @props = {}
  end

  def basename
    @name.sub(/\..*/, '')
  end

  def dup
    o = Opcode.new(@name.dup, @bin)
    o.bin    = @bin.dup if @bin.kind_of?(::Array)
    o.args   = @args.dup
    o.fields = @fields.dup
    o.props  = @props.dup
    o
  end
end

# defines an attribute self.backtrace (array of filename/lineno)
# and a method backtrace_str which dumps this array to a human-readable form
module Backtrace
  # array [file, lineno, file, lineno]
  # if file 'A' does #include 'B' you'll get ['A', linenoA, 'B', linenoB]
  attr_accessor :backtrace

  # builds a readable string from self.backtrace
  def backtrace_str
    Backtrace.backtrace_str(@backtrace)
  end

  # builds a readable backtrace string from an array of [file, lineno, file, lineno, ..]
  def self.backtrace_str(ary)
    return '' if not ary
    i = ary.length
    bt = ''
    while i > 0
      bt << ",\n\tincluded from " if ary[i]
      i -= 2
      bt << "#{ary[i].inspect} line #{ary[i+1]}"
    end
    bt
  end

  def exception(msg='syntax error')
    ParseError.new "at #{backtrace_str}: #{msg}"
  end
end

# an instruction: opcode name + arguments
class Instruction
  # arguments (cpu-specific objects)
  attr_accessor :args
  # hash of prefixes (unused in simple cpus)
  attr_accessor :prefix
  # name of the associated opcode
  attr_accessor :opname
  # reference to the cpu which issued this instruction (used for rendering)
  attr_accessor :cpu

  include Backtrace

  def initialize(cpu, opname=nil, args=[], pfx=nil, backtrace=nil)
    @cpu = cpu
    @opname = opname
    @args = args
    @prefix = pfx if pfx
    @backtrace = backtrace
  end

  # duplicates the argument list and prefix hash
  def dup
    Instruction.new(@cpu, (@opname.dup if opname), @args.dup, (@prefix.dup if prefix), (@backtrace.dup if backtrace))
  end
end

# all kind of data description (including repeated/uninitialized)
class Data
  # maps data type to Expression parameters (signedness/bit size)
  INT_TYPE = {'db' => :a8, 'dw' => :a16, 'dd' => :a32, 'dq' => :a64}

  # an Expression, an Array of Data, a String, or :uninitialized
  attr_accessor :data
  # the data type, from INT_TYPE (TODO store directly Expression parameters ?)
  attr_accessor :type
  # the repetition count of the data parameter (dup constructs)
  attr_accessor :count

  include Backtrace

  def initialize(type, data, count=1, backtrace=nil)
    @data, @type, @count, @backtrace = data, type, count, backtrace
  end
end

# a name for a location
class Label
  attr_accessor :name

  include Backtrace

  def initialize(name, backtrace=nil)
    @name, @backtrace = name, backtrace
  end
end

# alignment directive
class Align
  # the size to align to
  attr_accessor :val
  # the Data used to pad
  attr_accessor :fillwith

  include Backtrace

  def initialize(val, fillwith=nil, backtrace=nil)
    @val, @fillwith, @backtrace = val, fillwith, backtrace
  end
end

# padding directive
class Padding
  # Data used to pad
  attr_accessor :fillwith

  include Backtrace

  def initialize(fillwith=nil, backtrace=nil)
    @fillwith, @backtrace = fillwith, backtrace
  end
end

# offset directive
# can be used to fix padding length or to assert some code/data compiled length
class Offset
  # the assembler will arrange to make this pseudo-instruction
  # be at this offset from beginning of current section
  attr_accessor :val

  include Backtrace

  def initialize(val, backtrace=nil)
    @val, @backtrace = val, backtrace
  end
end

# the superclass of all real executable formats
# main methods:
#  self.decode(str) => decodes the file format (imports/relocs/etc), no asm disassembly
#  parse(source) => parses assembler source, fills self.source
#  assemble => assembles self.source in binary sections/segments/whatever
#  encode => builds imports/relocs tables, put all this together, links everything in self.encoded
class ExeFormat
  # array of Data/Instruction/Align/Padding/Offset/Label, populated in parse
  attr_accessor :cursource
  # contains the binary version of the compiled program (EncodedData)
  attr_accessor :encoded
  # hash of labels generated by new_label
  attr_accessor :unique_labels_cache

  # initializes self.cpu, creates an empty self.encoded
  def initialize(cpu=nil)
    @cpu = cpu
    @encoded = EncodedData.new
    @unique_labels_cache = {}
  end

  attr_writer :cpu	# custom reader
  def cpu
    @cpu ||= cpu_from_headers
  end

  # return the label name corresponding to the specified offset of the encodeddata, creates it if necessary
  def label_at(edata, offset, base = '')
    if not l = edata.inv_export[offset]
      edata.add_export(l = new_label(base), offset)
    end
    l
  end

  # creates a new label, that is guaranteed to never be returned again as long as this object (ExeFormat) exists
  def new_label(base = '')
    base = base.dup.tr('^a-zA-Z0-9_', '_')
    # use %x instead of to_s(16) for negative values
    base = (base << '_uuid' << ('%08x' % base.object_id)).freeze if base.empty? or @unique_labels_cache[base]
    @unique_labels_cache[base] = true
    base
  end

  # share self.unique_labels_cache with other, checks for conflicts, returns self
  def share_namespace(other)
    return self if other.unique_labels_cache.equal? @unique_labels_cache
    raise "share_ns #{(other.unique_labels_cache.keys & @unique_labels_cache.keys).inspect}" if !(other.unique_labels_cache.keys & @unique_labels_cache.keys).empty?
    @unique_labels_cache.update other.unique_labels_cache
    other.unique_labels_cache = @unique_labels_cache
    self
  end
end

# superclass for classes similar to Expression
# must define #bind, #reduce_rec, #match_rec, #externals
class ExpressionType
  def +(o) Expression[self, :+, o].reduce end
  def -(o) Expression[self, :-, o].reduce end
end

# handle immediate values, and arbitrary arithmetic/logic expression involving variables
# boolean values are treated as in C : true is 1, false is 0
# TODO replace #type with #size => bits + #type => [:signed/:unsigned/:any/:floating]
# TODO handle floats
class Expression < ExpressionType
  INT_SIZE = {}
  INT_MIN = {}
  INT_MAX = {}

  [8, 16, 32, 64].each { |sz|
    INT_SIZE["i#{sz}".to_sym] =
    INT_SIZE["u#{sz}".to_sym] =
    INT_SIZE["a#{sz}".to_sym] = sz

    INT_MIN["a#{sz}".to_sym] =
    INT_MIN["i#{sz}".to_sym] = -(1 << (sz-1))	# -0x8000
    INT_MIN["u#{sz}".to_sym] = 0

    INT_MAX["i#{sz}".to_sym] = (1 << (sz-1)) - 1	#  0x7fff
    INT_MAX["a#{sz}".to_sym] =
    INT_MAX["u#{sz}".to_sym] = (1 << sz) - 1	#  0xffff
  }

  # alternative constructor
  # in operands order, and allows nesting using sub-arrays
  # ex: Expression[[:-, 42], :*, [1, :+, [4, :*, 7]]]
  # with a single argument, return it if already an Expression, else construct a new one (using unary +/-)
  def self.[](l, op=nil, r=nil)
    if not r	# need to shift args
      if not op
        raise ArgumentError, 'invalid Expression[nil]' if not l
        return l if l.kind_of? Expression
        if l.kind_of?(::Numeric) and l < 0
          r = -l
          op = :'-'
        else
          r = l
          op = :'+'
        end
      else
        r = op
        op = l
      end
      l = nil
    else
      l = self[*l] if l.kind_of?(::Array)
    end
    r = self[*r] if r.kind_of?(::Array)
    new(op, r, l)
  end

  # checks if a given Expression/Integer is in the type range
  # returns true if it is, false if it overflows, and nil if cannot be determined (eg unresolved variable)
  def self.in_range?(val, type)
    val = val.reduce if val.kind_of? self
    return unless val.kind_of?(::Numeric)

    if INT_MIN[type]
      val == val.to_i and
      val >= INT_MIN[type] and val <= INT_MAX[type]
    end
  end

  # casts an unsigned value to a two-complement signed if the sign bit is set
  def self.make_signed(val, bitlength)
    case val
    when Integer
      val = val - (1 << bitlength) if val > 0 and val >> (bitlength - 1) == 1
    when Expression
      val = Expression[val, :-, [(1<<bitlength), :*, [[val, :>>, (bitlength-1)], :==, 1]]]
    end
    val
  end

  # the operator (symbol)
  attr_accessor :op
  # the lefthandside expression (nil for unary expressions)
  attr_accessor :lexpr
  # the righthandside expression
  attr_accessor :rexpr

  # basic constructor
  # XXX funny args order, you should use +Expression[]+ instead
  def initialize(op, rexpr, lexpr)
    raise ArgumentError, "Expression: invalid arg order: #{[lexpr, op, rexpr].inspect}" if not op.kind_of?(::Symbol)
    @op = op
    @lexpr = lexpr
    @rexpr = rexpr
  end

  # recursive check of equity using #==
  # will not match 1+2 and 2+1
  def ==(o)
    # shortcircuit recursion
    o.object_id == object_id or (o.kind_of?(Expression) and @op == o.op and @lexpr == o.lexpr and @rexpr == o.rexpr)
  end

  # make it useable as Hash key (see +==+)
  def hash
    (@lexpr.hash + @op.hash + @rexpr.hash) & 0x7fff_ffff
  end
  alias eql? ==

  # returns a new Expression with all variables found in the binding replaced with their value
  # does not check the binding's key class except for numeric
  # calls lexpr/rexpr #bind if they respond_to? it
  def bind(binding = {})
    if binding[self]
      return binding[self].dup
    end

    l = @lexpr
    r = @rexpr
    if l and binding[l]
      raise "internal error - bound #{l.inspect}" if l.kind_of?(::Numeric)
      l = binding[l]
    elsif l.kind_of? ExpressionType
      l = l.bind(binding)
    end
    if r and binding[r]
      raise "internal error - bound #{r.inspect}" if r.kind_of?(::Numeric)
      r = binding[r]
    elsif r.kind_of? ExpressionType
      r = r.bind(binding)
    end
    Expression.new(@op, r, l)
  end

  # bind in place (replace self.lexpr/self.rexpr with the binding value)
  # only recurse with Expressions (does not use respond_to?)
  def bind!(binding = {})
    if @lexpr.kind_of?(Expression)
      @lexpr.bind!(binding)
    elsif @lexpr
      @lexpr = binding[@lexpr] || @lexpr
    end
    if @rexpr.kind_of?(Expression)
      @rexpr.bind!(binding)
    elsif @rexpr
      @rexpr = binding[@rexpr] || @rexpr
    end
    self
  end

  # reduce_lambda is a callback called after the standard reduction procedure for custom algorithms
  # the lambda may return a new expression or nil (to keep the old expr)
  # exemple: lambda { |e| e.lexpr if e.kind_of? Expression and e.op == :& and e.rexpr == 0xffff_ffff }
  # returns old lambda
  def self.reduce_lambda(&b)
    old = @@reduce_lambda
    @@reduce_lambda = b if block_given?
    old
  end
  def self.reduce_lambda=(p)
    @@reduce_lambda = p
  end
  @@reduce_lambda = nil

  # returns a simplified copy of self
  # can return an +Expression+ or a +Numeric+, may return self
  # see +reduce_rec+ for simplifications description
  # if given a block, it will temporarily overwrite the global @@reduce_lambda XXX THIS IS NOT THREADSAFE
  def reduce(&b)
    old_rp, @@reduce_lambda = @@reduce_lambda, b if b
    case e = reduce_rec
    when Expression, Numeric; e
    else Expression[e]
    end
  ensure
    @@reduce_lambda = old_rp if b
  end

  # resolves logic operations (true || false, etc)
  # computes numeric operations (1 + 3)
  # expands substractions to addition of the opposite
  # reduces double-oppositions (-(-1) => 1)
  # reduces addition of 0 and unary +
  # canonicalize additions: put variables in the lhs, descend addition tree in the rhs => (a + (b + (c + 12)))
  # make formal reduction if finds somewhere in addition tree (a) and (-a)
  def reduce_rec
    l = @lexpr.kind_of?(ExpressionType) ? @lexpr.reduce_rec : @lexpr
    r = @rexpr.kind_of?(ExpressionType) ? @rexpr.reduce_rec : @rexpr

    if @@reduce_lambda
      l = @@reduce_lambda[l] || l if not @lexpr.kind_of? Expression
      r = @@reduce_lambda[r] || r if not @rexpr.kind_of? Expression
    end

    v =
    if r.kind_of?(::Numeric) and (not l or l.kind_of?(::Numeric))
      case @op
      when :+; l ? l + r : r
      when :-; l ? l - r : -r
      when :'!'; raise 'internal error' if l ; (r == 0) ? 1 : 0
      when :'~'; raise 'internal error' if l ; ~r
      when :'&&', :'||', :'>', :'<', :'>=', :'<=', :'==', :'!='
        raise 'internal error' if not l
        case @op
        when :'&&'; (l != 0) && (r != 0)
        when :'||'; (l != 0) || (r != 0)
        when :'>' ; l > r
        when :'>='; l >= r
        when :'<' ; l < r
        when :'<='; l <= r
        when :'=='; l == r
        when :'!='; l != r
        end ? 1 : 0
      else
        l.send(@op, r)
      end
    elsif rp = @@reduce_op[@op]
      rp[self, l, r]
    end

    ret = case v
    when nil
      # no dup if no new value
      (r == :unknown or l == :unknown) ? :unknown :
      ((r == @rexpr and l == @lexpr) ? self : Expression.new(@op, r, l))
    when Expression
      (v.lexpr == :unknown or v.rexpr == :unknown) ? :unknown : v
    else v
    end
    if @@reduce_lambda and ret.kind_of? ExpressionType and newret = @@reduce_lambda[ret] and newret != ret
      if newret.kind_of? ExpressionType
        ret = newret.reduce_rec
      else
        ret = newret
      end
    end
    ret
  end

  @@reduce_op = {
    :+    => lambda { |e, l, r| e.reduce_op_plus(l, r) },
    :-    => lambda { |e, l, r| e.reduce_op_minus(l, r) },
    :'&&' => lambda { |e, l, r| e.reduce_op_andand(l, r) },
    :'||' => lambda { |e, l, r| e.reduce_op_oror(l, r) },
    :>>   => lambda { |e, l, r| e.reduce_op_shr(l, r) },
    :<<   => lambda { |e, l, r| e.reduce_op_shl(l, r) },
    :'!'  => lambda { |e, l, r| e.reduce_op_not(l, r) },
    :==   => lambda { |e, l, r| e.reduce_op_eql(l, r) },
    :'!=' => lambda { |e, l, r| e.reduce_op_neq(l, r) },
    :^    => lambda { |e, l, r| e.reduce_op_xor(l, r) },
    :&    => lambda { |e, l, r| e.reduce_op_and(l, r) },
    :|    => lambda { |e, l, r| e.reduce_op_or(l, r) },
    :*    => lambda { |e, l, r| e.reduce_op_times(l, r) },
    :/    => lambda { |e, l, r| e.reduce_op_div(l, r) },
    :%    => lambda { |e, l, r| e.reduce_op_mod(l, r) },
  }


  def self.reduce_op
    @@reduce_op
  end

  def reduce_op_plus(l, r)
    if not l; r	# +x  => x
    elsif r == 0; l	# x+0 => x
    elsif l == :unknown or r == :unknown; :unknown
    elsif l.kind_of?(::Numeric)
      if r.kind_of? Expression and r.op == :+
        # 1+(x+y) => x+(y+1)
        Expression[r.lexpr, :+, [r.rexpr, :+, l]].reduce_rec
      else
        # 1+a => a+1
        Expression[r, :+, l].reduce_rec
      end
      # (a+b)+foo => a+(b+foo)
    elsif l.kind_of? Expression and l.op == :+; Expression[l.lexpr, :+, [l.rexpr, :+, r]].reduce_rec
    elsif l.kind_of? Expression and r.kind_of? Expression and l.op == :% and r.op == :% and l.rexpr.kind_of?(::Integer) and l.rexpr == r.rexpr
      Expression[[l.lexpr, :+, r.lexpr], :%, l.rexpr].reduce_rec
    elsif l.kind_of? Expression and l.op == :- and not l.lexpr
      reduce_rec_add_rec(r, l.rexpr)
    elsif l.kind_of? Expression and r.kind_of? Expression and l.op == :& and r.op == :& and l.rexpr.kind_of?(::Integer) and r.rexpr.kind_of?(::Integer) and l.rexpr & r.rexpr == 0
      # (a&0xf0)+(b&0x0f) => (a&0xf0)|(b&0x0f)
      Expression[l, :|, r].reduce_rec
    else
      reduce_rec_add_rec(r, Expression.new(:-, l, nil))
    end
  end

  def reduce_rec_add_rec(cur, neg_l)
    if neg_l == cur
      # -l found
      0
    elsif cur.kind_of?(Expression) and cur.op == :+
      # recurse
      if newl = reduce_rec_add_rec(cur.lexpr, neg_l)
        Expression[newl, cur.op, cur.rexpr].reduce_rec
      elsif newr = reduce_rec_add_rec(cur.rexpr, neg_l)
        Expression[cur.lexpr, cur.op, newr].reduce_rec
      end
    end
  end

  def reduce_op_minus(l, r)
    if l == :unknown or r == :unknown; :unknown
    elsif not l and r.kind_of? Expression and (r.op == :- or r.op == :+)
      if r.op == :- # no lexpr (reduced)
        # -(-x) => x
        r.rexpr
      else # :+ and lexpr (r is reduced)
        # -(a+b) => (-a)+(-b)
        Expression.new(:+, Expression.new(:-, r.rexpr, nil), Expression.new(:-, r.lexpr, nil)).reduce_rec
      end
    elsif l.kind_of? Expression and l.op == :+ and l.lexpr == r
      # shortcircuit for a common occurence [citation needed]
      # (a+b)-a
      l.rexpr
    elsif l
      # a-b => a+(-b)
      Expression[l, :+, [:-, r]].reduce_rec
    end
  end

  def reduce_op_andand(l, r)
    if l == 0	# shortcircuit eval
      0
    elsif l == 1
      Expression[r, :'!=', 0].reduce_rec
    elsif r == 0
      0	# XXX l could be a special ExprType with sideeffects ?
    end
  end

  def reduce_op_oror(l, r)
    if l.kind_of?(::Numeric) and l != 0	# shortcircuit eval
      1
    elsif l == 0
      Expression[r, :'!=', 0].reduce_rec
    elsif r == 0
      Expression[l, :'!=', 0].reduce_rec
    end
  end

  def reduce_op_shr(l, r)
    if l == 0; 0
    elsif r == 0; l
    elsif l.kind_of? Expression and l.op == :>>
      Expression[l.lexpr, :>>, [l.rexpr, :+, r]].reduce_rec
    elsif r.kind_of? Integer and l.kind_of? Expression and [:&, :|, :^].include? l.op
      # (a | b) << i => (a<<i | b<<i)
      Expression[[l.lexpr, :>>, r], l.op, [l.rexpr, :>>, r]].reduce_rec
    end
  end

  def reduce_op_shl(l, r)
    if l == 0; 0
    elsif r == 0; l
    elsif l.kind_of? Expression and l.op == :<<
      Expression[l.lexpr, :<<, [l.rexpr, :+, r]].reduce_rec
    elsif l.kind_of? Expression and l.op == :>> and r.kind_of? Integer and l.rexpr.kind_of? Integer
      # (a >> 1) << 1  ==  a & 0xfffffe
      if r == l.rexpr
        Expression[l.lexpr, :&, (-1 << r)].reduce_rec
      elsif r > l.rexpr
        Expression[[l.lexpr, :<<, r-l.rexpr], :&, (-1 << r)].reduce_rec
      else
        Expression[[l.lexpr, :>>, l.rexpr-r], :&, (-1 << r)].reduce_rec
      end
    elsif r.kind_of? Integer and l.kind_of? Expression and [:&, :|, :^].include? l.op
      # (a | b) << i => (a<<i | b<<i)
      Expression[[l.lexpr, :<<, r], l.op, [l.rexpr, :<<, r]].reduce_rec
    end
  end

  NEG_OP = {:'==' => :'!=', :'!=' => :'==', :< => :>=, :> => :<=, :<= => :>, :>= => :<}

  def reduce_op_not(l, r)
    if r.kind_of? Expression and nop = NEG_OP[r.op]
      Expression[r.lexpr, nop, r.rexpr].reduce_rec
    end
  end

  def reduce_op_eql(l, r)
    if l == r; 1
    elsif r == 0 and l.kind_of? Expression and nop = NEG_OP[l.op]
      Expression[l.lexpr, nop, l.rexpr].reduce_rec
    elsif r == 1 and l.kind_of? Expression and NEG_OP[l.op]
      l
    elsif r == 0 and l.kind_of? Expression and l.op == :+
      if l.rexpr.kind_of? Expression and l.rexpr.op == :- and not l.rexpr.lexpr
        Expression[l.lexpr, :==, l.rexpr.rexpr].reduce_rec
      elsif l.rexpr.kind_of?(::Integer)
        Expression[l.lexpr, :==, -l.rexpr].reduce_rec
      end
    end
  end

  def reduce_op_neq(l, r)
    if l == r; 0
    end
  end

  def reduce_op_xor(l, r)
    if l == :unknown or r == :unknown; :unknown
    elsif l == 0; r
    elsif r == 0; l
    elsif l == r; 0
    elsif r == 1 and l.kind_of? Expression and NEG_OP[l.op]
      Expression[nil, :'!', l].reduce_rec
    elsif l.kind_of?(::Numeric)
      if r.kind_of? Expression and r.op == :^
        # 1^(x^y) => x^(y^1)
        Expression[r.lexpr, :^, [r.rexpr, :^, l]].reduce_rec
      else
        # 1^a => a^1
        Expression[r, :^, l].reduce_rec
      end
    elsif l.kind_of? Expression and l.op == :^
      # (a^b)^c => a^(b^c)
      Expression[l.lexpr, :^, [l.rexpr, :^, r]].reduce_rec
    elsif r.kind_of? Expression and r.op == :^
      if r.rexpr == l
        # a^(a^b) => b
        r.lexpr
      elsif r.lexpr == l
        # a^(b^a) => b
        r.rexpr
      else
        # a^(b^(c^(a^d)))  =>  b^(a^(c^(a^d)))
        # XXX ugly..
        tr = r
        found = false
        while not found and tr.kind_of?(Expression) and tr.op == :^
          found = true if tr.lexpr == l or tr.rexpr == l
          tr = tr.rexpr
        end
        if found
          Expression[r.lexpr, :^, [l, :^, r.rexpr]].reduce_rec
        end
      end
    elsif l.kind_of?(Expression) and l.op == :& and l.rexpr.kind_of?(::Integer) and (l.rexpr & (l.rexpr+1)) == 0
      if r.kind_of?(::Integer) and r & l.rexpr == r
        # (a&0xfff)^12 => (a^12)&0xfff
        Expression[[l.lexpr, :^, r], :&, l.rexpr].reduce_rec
      elsif r.kind_of?(Expression) and r.op == :& and r.rexpr.kind_of?(::Integer) and r.rexpr == l.rexpr
        # (a&0xfff)^(b&0xfff) => (a^b)&0xfff
        Expression[[l.lexpr, :^, r.lexpr], :&, l.rexpr].reduce_rec
      end
    end
  end

  def reduce_op_and(l, r)
    if l == 0 or r == 0; 0
    elsif r == 1 and l.kind_of?(Expression) and [:'==', :'!=', :<, :>, :<=, :>=].include?(l.op)
      l
    elsif l == r; l
    elsif l.kind_of?(Integer); Expression[r, :&, l].reduce_rec
    elsif l.kind_of?(Expression) and l.op == :&; Expression[l.lexpr, :&, [l.rexpr, :&, r]].reduce_rec
    elsif l.kind_of?(Expression) and [:|, :^].include?(l.op) and r.kind_of?(Integer) and (l.op == :| or (r & (r+1)) != 0)
      # (a ^| b) & i => (a&i ^| b&i)
      Expression[[l.lexpr, :&, r], l.op, [l.rexpr, :&, r]].reduce_rec
    elsif r.kind_of?(::Integer) and l.kind_of?(Expression) and (r & (r+1)) == 0
      # foo & 0xffff
      case l.op
      when :+, :^
        if l.lexpr.kind_of?(Expression) and l.lexpr.op == :& and
          l.lexpr.rexpr.kind_of?(::Integer) and l.lexpr.rexpr & r == r
          # ((a&m) + b) & m  =>  (a+b) & m
          Expression[[l.lexpr.lexpr, l.op, l.rexpr], :&, r].reduce_rec
        elsif l.rexpr.kind_of?(Expression) and l.rexpr.op == :& and
          l.rexpr.rexpr.kind_of?(::Integer) and l.rexpr.rexpr & r == r
          # (a + (b&m)) & m  =>  (a+b) & m
          Expression[[l.lexpr, l.op, l.rexpr.lexpr], :&, r].reduce_rec
        else
          Expression[l, :&, r]
        end
      when :|
        # rol/ror composition
        reduce_rec_composerol l, r
      else
        Expression[l, :&, r]
      end
    end
  end

  # a check to see if an Expr is the composition of two rotations (rol eax, 4 ; rol eax, 6 => rol eax, 10)
  # this is a bit too ugly to stay in the main reduce_rec body.
  def reduce_rec_composerol(e, mask)
    m = Expression[['var', :sh_op, 'amt'], :|, ['var', :inv_sh_op, 'inv_amt']]
    if vars = e.match(m, 'var', :sh_op, 'amt', :inv_sh_op, 'inv_amt') and vars[:sh_op] == {:>> => :<<, :<< => :>>}[vars[:inv_sh_op]] and
       ((vars['amt'].kind_of?(::Integer) and  vars['inv_amt'].kind_of?(::Integer) and ampl = vars['amt'] + vars['inv_amt']) or
        (vars['amt'].kind_of? Expression and vars['amt'].op == :% and vars['amt'].rexpr.kind_of?(::Integer) and
         vars['inv_amt'].kind_of? Expression and vars['inv_amt'].op == :% and vars['amt'].rexpr == vars['inv_amt'].rexpr and ampl = vars['amt'].rexpr)) and
       mask == (1<<ampl)-1 and vars['var'].kind_of? Expression and	# it's a rotation

       vars['var'].op == :& and vars['var'].rexpr == mask and
      ivars = vars['var'].lexpr.match(m, 'var', :sh_op, 'amt', :inv_sh_op, 'inv_amt') and ivars[:sh_op] == {:>> => :<<, :<< => :>>}[ivars[:inv_sh_op]] and
       ((ivars['amt'].kind_of?(::Integer) and  ivars['inv_amt'].kind_of?(::Integer) and ampl = ivars['amt'] + ivars['inv_amt']) or
        (ivars['amt'].kind_of? Expression and ivars['amt'].op == :% and ivars['amt'].rexpr.kind_of?(::Integer) and
         ivars['inv_amt'].kind_of? Expression and ivars['inv_amt'].op == :% and ivars['amt'].rexpr == ivars['inv_amt'].rexpr and ampl = ivars['amt'].rexpr))
      if ivars[:sh_op] != vars[:sh_op]
        # ensure the rotations are the same orientation
        ivars[:sh_op], ivars[:inv_sh_op] = ivars[:inv_sh_op], ivars[:sh_op]
        ivars['amt'],  ivars['inv_amt']  = ivars['inv_amt'],  ivars['amt']
      end
      amt = Expression[[vars['amt'], :+, ivars['amt']], :%, ampl]
      invamt = Expression[[vars['inv_amt'], :+, ivars['inv_amt']], :%, ampl]
      Expression[[[[ivars['var'], :&, mask], vars[:sh_op], amt], :|, [[ivars['var'], :&, mask], vars[:inv_sh_op], invamt]], :&, mask].reduce_rec
    else
      Expression[e, :&, mask]
    end
  end

  def reduce_op_or(l, r)
    if    l == 0; r
    elsif r == 0; l
    elsif l == -1 or r == -1; -1
    elsif l == r; l
    elsif l.kind_of? Integer; Expression[r, :|, l].reduce_rec
    elsif l.kind_of? Expression and l.op == :|
      # (a|b)|c => a|(b|c)
      Expression[l.lexpr, :|, [l.rexpr, :|, r]].reduce_rec
    elsif l.kind_of? Expression and l.op == :& and r.kind_of? Expression and r.op == :& and l.lexpr == r.lexpr
      # (a&b)|(a&c) => a&(b|c)
      Expression[l.lexpr, :&, [l.rexpr, :|, r.rexpr]].reduce_rec
    end
  end

  def reduce_op_times(l, r)
    if    l == 0 or r == 0; 0
    elsif l == 1; r
    elsif r == 1; l
    elsif r.kind_of? Integer; Expression[r, :*, l].reduce_rec
    elsif r.kind_of? Expression and r.op == :*; Expression[[l, :*, r.lexpr], :*, r.rexpr].reduce_rec
    elsif l.kind_of? Integer and r.kind_of? Expression and r.op == :* and r.lexpr.kind_of? Integer; Expression[l*r.lexpr, :*, r.rexpr].reduce_rec	# XXX need & regsize..
    elsif l.kind_of? Integer and r.kind_of? Expression and r.op == :+ and r.rexpr.kind_of? Integer; Expression[[l, :*, r.lexpr], :+, l*r.rexpr].reduce_rec
    end
  end

  def reduce_op_div(l, r)
    if r == 0
    elsif r.kind_of? Integer and l.kind_of? Expression and l.op == :+ and l.rexpr.kind_of? Integer and l.rexpr % r == 0
      Expression[[l.lexpr, :/, r], :+, l.rexpr/r].reduce_rec
    elsif r.kind_of? Integer and l.kind_of? Expression and l.op == :* and l.lexpr % r == 0
      Expression[l.lexpr/r, :*, l.rexpr].reduce_rec
    end
  end

  def reduce_op_mod(l, r)
    if r.kind_of?(Integer) and r != 0 and (r & (r-1) == 0)
      Expression[l, :&, r-1].reduce_rec
    end
  end


  # a pattern-matching method
  # Expression[42, :+, 28].match(Expression['any', :+, 28], 'any') => {'any' => 42}
  # Expression[42, :+, 28].match(Expression['any', :+, 'any'], 'any') => false
  # Expression[42, :+, 42].match(Expression['any', :+, 'any'], 'any') => {'any' => 42}
  # vars can match anything except nil
  def match(target, *vars)
    match_rec(target, vars.inject({}) { |h, v| h.update v => nil })
  end

  def match_rec(target, vars)
    return false if not target.kind_of? Expression
    [target.lexpr, target.op, target.rexpr].zip([@lexpr, @op, @rexpr]) { |targ, exp|
      if targ and vars[targ]
        return false if exp != vars[targ]
      elsif targ and vars.has_key? targ
        return false if not vars[targ] = exp
      elsif targ.kind_of? ExpressionType
        return false if not exp.kind_of? ExpressionType or not exp.match_rec(targ, vars)
      else
        return false if targ != exp
      end
    }
    vars
  end

  # returns the array of non-numeric members of the expression
  # if a variables appears 3 times, it will be present 3 times in the returned array
  def externals
    a = []
    [@rexpr, @lexpr].each { |e|
      case e
      when ExpressionType; a.concat e.externals
      when nil, ::Numeric; a
      else a << e
      end
    }
    a
  end

  # returns the externals that appears in the expression, does not walk through other ExpressionType
  def expr_externals(include_exprs=false)
    a = []
    [@rexpr, @lexpr].each { |e|
      case e
      when Expression; a.concat e.expr_externals(include_exprs)
      when nil, ::Numeric; a
      when ExpressionType; include_exprs ? a << e : a
      else a << e
      end
    }
    a
  end

  def inspect
    "Expression[#{@lexpr.inspect.sub(/^Expression/, '') + ', ' if @lexpr}#{@op.inspect + ', ' if @lexpr or @op != :+}#{@rexpr.inspect.sub(/^Expression/, '')}]"
  end

  Unknown = self[:unknown]
end

# An Expression with a custom string representation
# used to show #define constants, struct offsets, func local vars, etc
class ExpressionString < ExpressionType
  attr_accessor :expr, :str, :type, :hide_str
  def reduce; expr.reduce; end
  def reduce_rec; expr.reduce_rec; end
  def bind(*a); expr.bind(*a); end
  def externals; expr.externals; end
  def expr_externals; expr.expr_externals; end
  def match_rec(*a); expr.match_rec(*a); end
  def initialize(expr, str, type=nil)
    @expr = Expression[expr]
    @str = str
    @type = type
  end
  def render_str ; [str] ; end
  def inspect ; "ExpressionString.new(#{@expr.inspect}, #{str.inspect}, #{type.inspect})" ; end
end

# an EncodedData relocation, specifies a value to patch in
class Relocation
  # the relocation value (an Expression)
  attr_accessor :target
  # the relocation expression type
  attr_accessor :type
  # the endianness of the relocation
  attr_accessor :endianness

  include Backtrace

  def initialize(target, type, endianness, backtrace = nil)
    raise ArgumentError, "bad args #{[target, type, endianness].inspect}" if not target.kind_of? Expression or not type.kind_of?(::Symbol) or not endianness.kind_of?(::Symbol)
    @target, @type, @endianness, @backtrace = target, type, endianness, backtrace
  end

  # fixup the encodeddata with value (reloc starts at off)
  def fixup(edata, off, value)
    str = Expression.encode_imm(value, @type, @endianness, @backtrace)
    edata.fill off
    edata.data[off, str.length] = str
  end

  # size of the relocation field, in bytes
  def length
    Expression::INT_SIZE[@type]/8
  end
end

# a String-like, with export/relocation informations added
class EncodedData
  # string with raw data
  attr_accessor :data
  # hash, key = offset within data, value = +Relocation+
  attr_accessor :reloc
  # hash, key = export name, value = offset within data - use add_export to update
  attr_accessor :export
  # hash, key = offset, value = 1st export name
  attr_accessor :inv_export
  # virtual size of data (all 0 by default, see +fill+)
  attr_accessor :virtsize
  # arbitrary pointer, often used when decoding immediates
  # may be initialized with an export value
  attr_reader   :ptr	# custom writer
  def ptr=(p) @ptr = @export[p] || p end

  # opts' keys in :reloc, :export, :virtsize, defaults to empty/empty/data.length
  def initialize(data='', opts={})
    if data.respond_to?(:force_encoding) and data.encoding.name != 'ASCII-8BIT' and data.length > 0
      puts "Forcing edata.data.encoding = BINARY at", caller if $DEBUG
      data = data.dup.force_encoding('binary')
    end
    @data     = data
    @reloc    = opts[:reloc]    || {}
    @export   = opts[:export]   || {}
    @inv_export = @export.invert
    @virtsize = opts[:virtsize] || @data.length
    @ptr = 0
  end

  def add_export(label, off=@ptr, set_inv=false)
    @export[label] = off
    if set_inv or not @inv_export[off]
      @inv_export[off] = label
    end
    label
  end

  def del_export(label, off=@export[label])
    @export.delete label
    if e = @export.index(off)
      @inv_export[off] = e
    else
      @inv_export.delete off
    end
  end

  # returns the size of raw data, that is [data.length, last relocation end].max
  def rawsize
    [@data.length, *@reloc.map { |off, rel| off + rel.length } ].max
  end
  # String-like
  alias length virtsize
  # String-like
  alias size virtsize

  def empty?
    @virtsize == 0
  end

  def eos?
    ptr.to_i >= @virtsize
  end

  # returns a copy of itself, with reloc/export duped (but not deep)
  def dup
    self.class.new @data.dup, :reloc => @reloc.dup, :export => @export.dup, :virtsize => @virtsize
  end

  # resolve relocations:
  # calculate each reloc target using Expression#bind(binding)
  # if numeric, replace the raw data with the encoding of this value (+fill+s preceding data if needed) and remove the reloc
  # if replace_target is true, the reloc target is replaced with its bound counterpart
  def fixup_choice(binding, replace_target)
    return if binding.empty?
    @reloc.keys.each { |off|
      val = @reloc[off].target.bind(binding).reduce
      if val.kind_of? Integer
        reloc = @reloc[off]
        reloc.fixup(self, off, val)
        @reloc.delete(off)	# delete only if not overflowed
      elsif replace_target
        @reloc[off].target = val
      end
    }
  end

  # +fixup_choice+ binding, false
  def fixup(binding)
    fixup_choice(binding, false)
  end

  # +fixup_choice+ binding, true
  def fixup!(binding)
    fixup_choice(binding, true)
  end

  # returns a default binding suitable for use in +fixup+
  # every export is expressed as base + offset
  # base defaults to the first export name + its offset
  def binding(base = nil)
    if not base
      key = @export.index(@export.values.min)
      return {} if not key
      base = (@export[key] == 0 ? key : Expression[key, :-, @export[key]])
    end
    binding = {}
    @export.each { |n, o| binding.update n => Expression.new(:+, o, base) }
    binding
  end

  # returns an array of variables that needs to be defined for a complete #fixup
  # ie the list of externals for all relocations
  def reloc_externals(interns = @export.keys)
    @reloc.values.map { |r| r.target.externals }.flatten.uniq - interns
  end

  # returns the offset where the relocation for target t is to be applied
  def offset_of_reloc(t)
    t = Expression[t]
    @reloc.keys.find { |off| @reloc[off].target == t }
  end

  # fill virtual space by repeating pattern (String) up to len
  # expand self if len is larger than self.virtsize
  def fill(len = @virtsize, pattern = [0].pack('C'))
    @virtsize = len if len > @virtsize
    @data = @data.to_str.ljust(len, pattern) if len > @data.length
  end

  # rounds up virtsize to next multiple of len
  def align(len, pattern=nil)
    @virtsize = EncodedData.align_size(@virtsize, len)
    fill(@virtsize, pattern) if pattern
  end

  # returns the value val rounded up to next multiple of len
  def self.align_size(val, len)
    return val if len == 0
    ((val + len - 1) / len).to_i * len
  end

  # concatenation of another +EncodedData+ (or nil/Fixnum/anything supporting String#<<)
  def <<(other)
    case other
    when nil
    when ::Fixnum
      fill
      @data = @data.to_str if not @data.kind_of? String
      @data << other
      @virtsize += 1
    when EncodedData
      fill if not other.data.empty?
      other.reloc.each  { |k, v| @reloc[k + @virtsize] = v  } if not other.reloc.empty?
      if not other.export.empty?
        other.export.each { |k, v|
          if @export[k] and @export[k] != v + @virtsize
            cf = (other.export.keys & @export.keys).find_all { |k_| other.export[k_] != @export[k_] - @virtsize }
            raise "edata merge: label conflict #{cf.inspect}"
          end
          @export[k] = v + @virtsize
        }
        other.inv_export.each { |k, v| @inv_export[@virtsize + k] = v }
      end
      if @data.empty?; @data = other.data.dup
      elsif not @data.kind_of?(String); @data = @data.to_str << other.data
      else @data << other.data
      end
      @virtsize += other.virtsize
    else
      fill
      if other.respond_to?(:force_encoding) and other.encoding.name != 'ASCII-8BIT'
        puts "Forcing edata.data.encoding = BINARY at", caller if $DEBUG
        other = other.dup.force_encoding('binary')
      end
      if @data.empty?; @data = other.dup
      elsif not @data.kind_of?(String); @data = @data.to_str << other
      else @data << other
      end
      @virtsize += other.length
    end

    self
  end

  # equivalent to dup << other, filters out Integers & nil
  def +(other)
    raise ArgumentError if not other or other.kind_of?(Integer)
    dup << other
  end

  # slice
  def [](from, len=nil)
    if not len and from.kind_of? Range
      b = from.begin
      e = from.end
      b = @export[b] if @export[b]
      e = @export[e] if @export[e]
      b = b + @virtsize if b < 0
      e = e + @virtsize if e < 0
      len = e - b
      len += 1 if not from.exclude_end?
      from = b
    end
    from = @export[from] if @export[from]
    from = from + @virtsize if from < 0
    return if from > @virtsize or from < 0

    return @data[from] if not len
    len = @virtsize - from if from+len > @virtsize
    ret = EncodedData.new @data[from, len]
    ret.virtsize = len
    @reloc.each { |o, r|
      ret.reloc[o - from] = r if o >= from and o + r.length <= from+len
    }
    @export.each { |e_, o|
      ret.export[e_] = o - from if o >= from and o <= from+len		# XXX include end ?
    }
    @inv_export.each { |o, e_|
      ret.inv_export[o-from] = e_ if o >= from and o <= from+len
    }
    ret
  end

  # slice replacement, supports size change (shifts following relocs/exports)
  # discards old exports/relocs from the overwritten space
  def []=(from, len, val=nil)
    if not val
      val = len
      len = nil
    end
    if not len and from.kind_of?(::Range)
      b = from.begin
      e = from.end
      b = @export[b] if @export[b]
      e = @export[e] if @export[e]
      b = b + @virtsize if b < 0
      e = e + @virtsize if e < 0
      len = e - b
      len += 1 if not from.exclude_end?
      from = b
    end
    from = @export[from] || from
    raise "invalid offset #{from}" if not from.kind_of?(::Integer)
    from = from + @virtsize if from < 0

    if not len
      val = val.chr if val.kind_of?(::Integer)
      len = val.length
    end
    raise "invalid slice length #{len}" if not len.kind_of?(::Integer) or len < 0

    if from >= @virtsize
      len = 0
    elsif from+len > @virtsize
      len = @virtsize-from
    end

    val = EncodedData.new << val

    # remove overwritten metadata
    @export.delete_if { |name, off| off > from and off < from + len }
    @reloc.delete_if { |off, rel| off - rel.length > from and off < from + len }
    # shrink/grow
    if val.length != len
      diff = val.length - len
      @export.keys.each { |name| @export[name] = @export[name] + diff if @export[name] > from }
      @inv_export.keys.each { |off| @inv_export[off+diff] = @inv_export.delete(off) if off > from }
      @reloc.keys.each { |off| @reloc[off + diff] = @reloc.delete(off) if off > from }
      if @virtsize >= from+len
        @virtsize += diff
      end
    end

    @virtsize = from + val.length if @virtsize < from + val.length

    if from + len < @data.length	# patch real data
      val.fill
      @data[from, len] = val.data
    elsif not val.data.empty?	# patch end of real data
      @data << ([0].pack('C')*(from-@data.length)) if @data.length < from
      @data[from..-1] = val.data
    else				# patch end of real data with fully virtual
      @data = @data[0, from]
    end
    val.export.each { |name, off| @export[name] = from + off }
    val.inv_export.each { |off, name| @inv_export[from+off] = name }
    val.reloc.each { |off, rel| @reloc[from + off] = rel }
  end

  # replace a portion of self
  # from/to may be Integers (offsets) or labels (from self.export)
  # content is a String or an EncodedData, which will be inserted in the specified location (padded if necessary)
  # raise if the string does not fit in.
  def patch(from, to, content)
    from = @export[from] || from
    raise "invalid offset specification #{from}" if not from.kind_of? Integer
    to = @export[to] || to
    raise "invalid offset specification #{to}" if not to.kind_of? Integer
    raise EncodeError, 'cannot patch data: new content too long' if to - from < content.length
    self[from, content.length] = content
  end

  # returns a list of offsets where /pat/ can be found inside @data
  # scan is done per chunk of chunksz bytes, with a margin for chunk-overlapping patterns
  # yields each offset found, and only include it in the result if the block returns !false
  def pattern_scan(pat, chunksz=nil, margin=nil)
    chunksz ||= 4*1024*1024 # scan 4MB at a time
    margin  ||= 65536        # add this much bytes at each chunk to find /pat/ over chunk boundaries
    pat = Regexp.new(Regexp.escape(pat)) if pat.kind_of?(::String)

    found = []
    chunkoff = 0
    while chunkoff < @data.length
      chunk = @data[chunkoff, chunksz+margin].to_str
      off = 0
      while match = chunk[off..-1].match(pat)
        off += match.pre_match.length
        m_l = match[0].length
        break if off >= chunksz	# match fully in margin
        match_addr = chunkoff + off
        found << match_addr if not block_given? or yield(match_addr)
        off += m_l
      end
      chunkoff += chunksz
    end
    found
  end
end
end
