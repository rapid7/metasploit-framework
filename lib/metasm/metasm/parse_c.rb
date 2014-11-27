#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/preprocessor'

module Metasm
# c parser
# inspired from http://www.math.grin.edu/~stone/courses/languages/C-syntax.xhtml
module C
  Keyword = %w[struct union enum  if else for while do switch goto
      register extern auto static typedef  const volatile
      void int float double char  signed unsigned long short
      case continue break return default  __attribute__
      asm __asm __asm__ sizeof typeof
      __declspec __cdecl __stdcall __fastcall __noreturn
      inline __inline __inline__ __volatile__
      __int8 __int16 __int32 __int64
      __builtin_offsetof
  ].inject({}) { |h, w| h.update w => true }

  class Statement
  end

  module Typed	# allows quick testing whether an object is an CExpr or a Variable
  end

  class Block < Statement
    attr_accessor :symbol	# hash name => Type/Variable/enum value
    attr_accessor :struct	# hash name => Struct/Union/Enum
    attr_accessor :outer	# parent block
    attr_accessor :statements	# array of Statement/Declaration
    attr_accessor :anonymous_enums	# array of anonymous Enum

    def initialize(outer, statements=[], symbol={}, struct={})
      @outer = outer
      @statements = statements
      @symbol = symbol
      @struct = struct
    end

    def struct_ancestors
      @outer ? @outer.struct_ancestors.merge(@struct) : @struct
    end

    def symbol_ancestors
      @outer ? @outer.symbol_ancestors.merge(@symbol) : @symbol
    end
  end

  module Attributes
    attr_accessor :attributes

    DECLSPECS = %w[cdecl stdcall fastcall inline naked thiscall noreturn]

    # parses a sequence of __attribute__((anything)) into self.attributes (array of string)
    def parse_attributes(parser, allow_declspec = false)
      while tok = parser.skipspaces and tok.type == :string
          case keyword = tok.raw
          when '__attribute__', '__declspec'	# synonymous: __attribute__((foo)) == __declspec(foo)
        raise tok || parser if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
        raise tok || parser if keyword == '__attribute__' and (not tok = parser.skipspaces or tok.type != :punct or tok.raw != '(')
        nest = 0
        attrib = ''
        loop do
          raise parser if not tok = parser.skipspaces
          if tok.type == :punct and tok.raw == ')'
            if nest == 0
              raise tok || parser if keyword == '__attribute__' and (not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')')
              break
            else
              nest -= 1
            end
          elsif tok.type == :punct and tok.raw == '('
            nest += 1
          elsif nest == 0 and tok.type == :punct and tok.raw == ','
            raise tok || parser if not allow_declspec and DECLSPECS.include? attrib
            add_attribute attrib
            attrib = ''
            next
          end
          attrib << tok.raw
        end
        raise tok || parser, "attr #{attrib.inspect} not allowed here" if not allow_declspec and DECLSPECS.include? attrib
          else
            if allow_declspec and DECLSPECS.include? keyword.gsub('_', '')
              attrib = keyword.gsub('_', '')
            else break
            end
          end
          add_attribute(attrib)
      end
      parser.unreadtok tok
    end

    # checks if the object has an attribute in its attribute list
    def has_attribute(attr)
      attributes.to_a.include? attr
    end

    # adds an attribute to the object attribute list if it is not already in it
    def add_attribute(attr)
      (@attributes ||= []) << attr  if not has_attribute(attr)
    end

    # checks if the object has an attributes a la __attribute__((attr(stuff))), returns 'stuff' (raw, no split on ',' or anything)
    def has_attribute_var(attr)
      $1 if attributes.to_a.find { |a| a =~ /^#{attr}\((.*)\)$/ }
    end
  end

  class Type
    include Attributes
    attr_accessor :qualifier	# const volatile

    def pointer? ;    false end
    def arithmetic? ; false end
    def integral? ;   false end
    def float? ;      false end
    def void? ;       false end
    def base ;        self  end
    def untypedef ;   self  end

    def parse_initializer(parser, scope)
      raise parser, 'expr expected' if not ret = CExpression.parse(parser, scope, false)
      p, i = pointer?, integral?
      r = ret.reduce(parser) if p or i
      if (not p and not i) or (i and not r.kind_of? ::Integer) or (p and r != 0)
        parser.check_compatible_type(parser, ret.type, self)
      end
      ret
    end

    def parse_initializer_designator(parser, scope, value, idx, root=true)
      if not root and (not nt = parser.skipspaces or nt.type != :punct or nt.raw != '=')
        raise nt || parser, '"=" expected'
      end
      value[idx] = parse_initializer(parser, scope)
      idx + 1
    end
  end
  class BaseType < Type
    attr_accessor :name		# :int :long :longlong :short :double :longdouble :float :char :void :__int8/16/32/64
    attr_accessor :specifier	# sign specifier only

    def arithmetic? ; @name != :void end
    def integral? ; [:char, :short, :int, :long, :longlong, :ptr,
      :__int8, :__int16, :__int32, :__int64].include? @name end
    def signed? ; specifier != :unsigned end
    def float? ; [:float, :double, :longdouble].include? @name end
    def void? ; @name == :void end
    def align(parser) @name == :double ? 4 : parser.typesize[@name] end

    def initialize(name, *specs)
      @name = name
      specs.each { |s|
        case s
        when :const, :volatile; (@qualifier ||= []) << s
        when :signed, :unsigned; @specifier = s
        when nil
        else raise "internal error, got #{name.inspect} #{specs.inspect}"
        end
      }
    end

    def ==(o)
      o.object_id == self.object_id or
      (o.class == self.class and o.name == self.name and o.specifier == self.specifier and o.attributes == self.attributes)
    end
  end
  class TypeDef < Type
    attr_accessor :name
    attr_accessor :type
    attr_accessor :backtrace

    def initialize(name, type, backtrace)
      @name, @type, @backtrace = name, type, backtrace
    end

    def parse_initializer(parser, scope)
      @type.parse_initializer(parser, scope)
    end

    def pointer? ;    @type.pointer?      end
    def arithmetic? ; @type.arithmetic?   end
    def integral? ;   @type.integral?     end
    def signed? ;     @type.signed?       end	# relevant only if integral? returns true
    def float? ;      @type.float?        end
    def void? ;       @type.void?         end
    def untypedef ;   @type.untypedef     end
    def align(parser) @type.align(parser) end	# XXX __attribute__ ?
    def pointed ;     @type.pointed       end
  end
  class Function < Type
    attr_accessor :type		# return type
    attr_accessor :args		# [name, Variable]
    attr_accessor :varargs		# true/false

    def initialize(type=nil, args=nil)
      @type = type
      @args = args if args
    end

    def base ; @type.base ; end
  end
  class Union < Type
    attr_accessor :members		# [Variable]
    attr_accessor :bits		# [bits] or nil
    attr_accessor :name
    attr_accessor :backtrace

    attr_accessor :fldoffset, :fldbitoffset, :fldlist

    def align(parser) @members.to_a.map { |m| m.type.align(parser) }.max end

    # there is only one instance of a given named struct per parser
    # so we just compare struct names here
    # for comparison between parsers, see #compare_deep
    def ==(o)
      o.object_id == self.object_id or
      (o.class == self.class and o.name == self.name and ((o.name and true) or compare_deep(o)))
    end

    # compare to another structure, comparing members recursively (names and type)
    # returns true if the self is same as o
    def compare_deep(o, seen = [])
      return true if o.object_id == self.object_id
      return if o.class != self.class or o.name != self.name or o.attributes != self.attributes
      o.members.to_a.zip(self.members.to_a).each { |om, sm|
        return if om.name != sm.name
        return if om.type != sm.type
        if om.type.pointer?
          ot = om.type
          st = sm.type
          500.times {	# limit for selfpointers (shouldnt happen)
            break if not ot.pointer?
            ot = ot.pointed.untypedef
            st = st.pointed.untypedef
          }
          if ot.kind_of?(C::Union) and ot.name and not seen.include?(ot)
            return if not st.compare_deep(ot, seen+[ot])
          end
        end
      }
      true
    end

    def findmember(name, igncase=false)
      raise 'undefined structure' if not members
      return @fldlist[name] if fldlist and @fldlist[name]

      name = name.downcase if igncase
      if m = @members.find { |m_| (n = m_.name) and (igncase ? n.downcase : n) == name }
        return m
      else
        @members.each { |m_|
          if t = m_.type.untypedef and t.kind_of? Union and mm = t.findmember(name, igncase)
            return mm
          end
        }
      end

      nil
    end

    def offsetof(parser, name)
      raise parser, 'undefined structure' if not members
      update_member_cache(parser) if not fldlist
      return 0 if @fldlist[name]

      if name.kind_of?(Variable)
        return 0 if @members.include? name
        raise ParseError, 'unknown union member'
      end

      raise parser, 'unknown union member' if not findmember(name)

      @members.find { |m|
        m.type.untypedef.kind_of? Union and m.type.untypedef.findmember(name)
      }.type.untypedef.offsetof(parser, name)
    end

    def bitoffsetof(parser, name)
      raise parser, 'undefined structure' if not members
      update_member_cache(parser) if not fldlist
      return if @fldlist[name] or @members.include?(name)
      raise parser, 'undefined union' if not @members
      raise parser, 'unknown union member' if not findmember(name)

      @members.find { |m|
        m.type.untypedef.kind_of? Union and m.type.untypedef.findmember(name)
      }.type.untypedef.bitoffsetof(parser, name)
    end

    def parse_members(parser, scope)
      @fldlist = nil if fldlist	# invalidate fld offset cache
      @members = []
      # parse struct/union members in definition
      loop do
        raise parser if not tok = parser.skipspaces
        break if tok.type == :punct and tok.raw == '}'
        parser.unreadtok tok

        raise tok, 'invalid struct member type' if not basetype = Variable.parse_type(parser, scope)
        loop do
          member = basetype.dup
          member.parse_declarator(parser, scope)
          member.type.length ||= 0 if member.type.kind_of?(Array)	# struct { char blarg[]; };
          raise member.backtrace, 'member redefinition' if member.name and @members.find { |m| m.name == member.name }
          @members << member

          raise tok || parser if not tok = parser.skipspaces or tok.type != :punct

          if tok.raw == ':'	# bits
            raise tok, 'bad type for bitslice' if not member.type.integral?
            bits = nil
            raise tok, "bad bit count #{bits.inspect}" if not bits = CExpression.parse(parser, scope, false) or
              not bits.constant? or !(bits = bits.reduce(parser)).kind_of? ::Integer
            #raise tok, 'need more bits' if bits > 8*parser.sizeof(member)
            # WORD wReserved:17; => yay windows.h
            (@bits ||= [])[@members.length-1] = bits
            raise tok || parser, '"," or ";" expected' if not tok = parser.skipspaces or tok.type != :punct
          end

          case tok.raw
          when ';'; break
          when ','
          when '}'; parser.unreadtok(tok); break
          else raise tok, '"," or ";" expected'
          end
        end
      end
      parse_attributes(parser)
    end

    # updates the @fldoffset / @fldbitoffset hash storing the offset of members
    def update_member_cache(parser)
      @fldlist = {}
      @members.to_a.each { |m|
        @fldlist[m.name] = m if m.name
      }
    end

    def parse_initializer(parser, scope)
      if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
        # struct x toto = { 1, .4, .member[0][6].bla = 12 };
        raise tok, 'undefined struct' if not @members
        ret = []
        if tok = parser.skipspaces and (tok.type != :punct or tok.raw != '}')
          parser.unreadtok tok
          idx = 0
          loop do
            idx = parse_initializer_designator(parser, scope, ret, idx, true)
            raise tok || parser, '"," or "}" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
            break if tok.raw == '}'
            raise tok, 'struct is smaller than that' if idx >= @members.length
          end
        end
        ret
      else
        parser.unreadtok tok
        super(parser, scope)
      end
    end

    # parses a designator+initializer eg '.toto = 4' or '.tutu[42][12].bla = 16' or (root ? '4' : '=4')
    def parse_initializer_designator(parser, scope, value, idx, root=true)
      if nt = parser.skipspaces and nt.type == :punct and nt.raw == '.' and
          nnt = parser.skipspaces and nnt.type == :string and
          findmember(nnt.raw)
        raise nnt, 'unhandled indirect initializer' if not nidx = @members.index(@members.find { |m| m.name == nnt.raw })	# TODO
        if not root
          value[idx] ||= []	# AryRecorder may change [] to AryRec.new, can't do v = v[i] ||= []
          value = value[idx]
        end
        idx = nidx
        @members[idx].type.untypedef.parse_initializer_designator(parser, scope, value, idx, false)
      else
        parser.unreadtok nnt
        if root
          parser.unreadtok nt
          value[idx] = @members[idx].type.parse_initializer(parser, scope)
        else
          raise nt || parser, '"=" expected' if not nt or nt.type != :punct or nt.raw != '='
          value[idx] = parse_initializer(parser, scope)
        end
      end
      idx + 1
    end

    # resolve structptr + offset into 'str.membername'
    # handles 'var.substruct1.array[12].foo'
    # updates str
    # returns the final member type itself
    # works for Struct/Union/Array
    def expand_member_offset(c_parser, off, str)
      # XXX choose in members, check sizeof / prefer structs
      m = @members.first
      str << '.' << m.name if m.name
      if m.type.respond_to?(:expand_member_offset)
        m.type.expand_member_offset(c_parser, off, str)
      else
        m.type
      end
    end
  end
  class Struct < Union
    attr_accessor :pack

    def align(parser) [@members.to_a.map { |m| m.type.align(parser) }.max || 1, (pack || 8)].min end

    def offsetof(parser, name)
      raise parser, 'undefined structure' if not members
      update_member_cache(parser) if not fldlist
      return @fldoffset[name] if @fldoffset[name]
      return @fldoffset[name.name] if name.respond_to?(:name) and @fldoffset[name.name]

      # this is almost never reached, only for <struct>.offsetof(anonymoussubstructmembername)
      raise parser, 'unknown structure member' if (name.kind_of?(::String) ?  !findmember(name) : !@members.include?(name))

      indirect = true if name.kind_of?(::String) and not @fldlist[name]

      al = align(parser)
      off = 0
      bit_off = 0
      isz = nil

      @members.each_with_index { |m, i|
        if bits and b = @bits[i]
          if not isz
            mal = [m.type.align(parser), al].min
            off = (off + mal - 1) / mal * mal
          end
          isz = parser.sizeof(m)
          if b == 0 or (bit_off > 0 and bit_off + b > 8*isz)
            bit_off = 0
            mal = [m.type.align(parser), al].min
            off = (off + isz + mal - 1) / mal * mal
          end
          break if m.name == name or m == name
          bit_off += b
        else
          if isz
            off += isz
            bit_off = 0
            isz = nil
          end
          mal = [m.type.align(parser), al].min
          off = (off + mal - 1) / mal * mal
          if m.name == name or m == name
            break
          elsif indirect and m.type.untypedef.kind_of? Union and m.type.untypedef.findmember(name)
            off += m.type.untypedef.offsetof(parser, name)
            break
          else
            off += parser.sizeof(m)
          end
        end
      }
      off
    end

    # returns the [bitoffset, bitlength] of the field if it is a bitfield
    # this should be added to the offsetof(field)
    def bitoffsetof(parser, name)
      raise parser, 'undefined structure' if not members
      update_member_cache(parser) if not fldlist
      return @fldbitoffset[name] if fldbitoffset and @fldbitoffset[name]
      return @fldbitoffset[name.name] if fldbitoffset and name.respond_to?(:name) and @fldbitoffset[name.name]
      return if @fldlist[name] or @members.include?(name)
      raise parser, 'undefined union' if not @members
      raise parser, 'unknown union member' if not findmember(name)

      @members.find { |m|
        m.type.untypedef.kind_of?(Union) and m.type.untypedef.findmember(name)
      }.type.untypedef.bitoffsetof(parser, name)
    end

    # returns the @member element that has offsetof(m) == off
    def findmember_atoffset(parser, off)
      return if not members
      update_member_cache(parser) if not fldlist
      if m = @fldoffset.index(off)
        @fldlist[m]
      end
    end

    def parse_members(parser, scope)
      super(parser, scope)

      if has_attribute 'packed'
        @pack = 1
      elsif p = has_attribute_var('pack')
        @pack = p[/\d+/].to_i
        raise parser, "illegal struct pack(#{p})" if @pack == 0
      end
    end

    # updates the @fldoffset / @fldbitoffset hash storing the offset of members
    def update_member_cache(parser)
      super(parser)

      @fldoffset = {}
      @fldbitoffset = {} if fldbitoffset

      al = align(parser)
      off = 0
      bit_off = 0
      isz = nil

      @members.each_with_index { |m, i|
        if bits and b = @bits[i]
          if not isz
            mal = [m.type.align(parser), al].min
            off = (off + mal - 1) / mal * mal
          end
          isz = parser.sizeof(m)
          if b == 0 or (bit_off > 0 and bit_off + b > 8*isz)
            bit_off = 0
            mal = [m.type.align(parser), al].min
            off = (off + isz + mal - 1) / mal * mal
          end
          if m.name
            @fldoffset[m.name] = off
            @fldbitoffset ||= {}
            @fldbitoffset[m.name] = [bit_off, b]
          end
          bit_off += b
        else
          if isz
            off += isz
            bit_off = 0
            isz = nil
          end
          mal = [m.type.align(parser), al].min
          off = (off + mal - 1) / mal * mal
          @fldoffset[m.name] = off if m.name
          off += parser.sizeof(m)
        end
      }
    end

    # see Union#expand_member_offset
    def expand_member_offset(c_parser, off, str)
      members.to_a.each { |m|
        mo = offsetof(c_parser, m)
        if mo == off or mo + c_parser.sizeof(m) > off
          if bitoffsetof(c_parser, m)
            # ignore bitfields
            str << "+#{off}" if off > 0
            return self
          end

          str << '.' << m.name if m.name
          if m.type.respond_to?(:expand_member_offset)
            return m.type.expand_member_offset(c_parser, off-mo, str)
          else
            return m.type
          end
        elsif mo > off
          break
        end
      }
      # XXX that works only for pointer-style str
      str << "+#{off}" if off > 0
      nil
    end
  end
  class Enum < Type
    # name => value
    attr_accessor :members
    attr_accessor :name
    attr_accessor :backtrace

    def align(parser) BaseType.new(:int).align(parser) end

    def arithmetic?; true end
    def integral?; true end
    def signed?; false end

    def parse_members(parser, scope)
      val = -1
      @members = {}
      loop do
        raise parser if not tok = parser.skipspaces
        break if tok.type == :punct and tok.raw == '}'

        name = tok.raw
        raise tok, 'bad enum name' if tok.type != :string or Keyword[name] or (?0..?9).include?(name[0])

        raise parser if not tok = parser.skipspaces
        if tok.type == :punct and tok.raw == '='
          raise tok || parser if not val = CExpression.parse(parser, scope, false) or not val = val.reduce(parser) or not tok = parser.skipspaces
        else
          val += 1
        end
        raise tok, "enum value #{name} redefinition" if scope.symbol[name] and scope.symbol[name] != val
        @members[name] = val
        scope.symbol[name] = val

        if tok.type == :punct and tok.raw == '}'
          break
        elsif tok.type == :punct and tok.raw == ','
        else raise tok, '"," or "}" expected'
        end
      end
      parse_attributes(parser)
    end

    def compare_deep(o)
      return true if o.object_id == self.object_id
      return if o.class != self.class or o.name != self.name or o.attributes != self.attributes
      members == o.members
    end
  end
  class Pointer < Type
    attr_accessor :type

    def initialize(type=nil)
      @type = type
    end

    def pointer? ; true ; end
    def arithmetic? ; true ; end
    def base ; @type.base ; end
    def align(parser) BaseType.new(:ptr).align(parser) end
    def pointed ; @type end

    def ==(o)
      o.class == self.class and o.type == self.type
    end
  end
  class Array < Pointer
    attr_accessor :length

    def initialize(type=nil, length=nil)
      super(type)
      @length = length if length
    end

    def align(parser) @type.align(parser) end

    def parse_initializer(parser, scope)
      raise parser, 'cannot initialize dynamic array' if @length.kind_of? CExpression
      if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
        # struct x foo[] = { { 4 }, [12].tutu = 2 };
        ret = []
        if tok = parser.skipspaces and (tok.type != :punct or tok.raw != '}')
          parser.unreadtok tok
          idx = 0
          loop do
            idx = parse_initializer_designator(parser, scope, ret, idx, true)
            raise tok || parser, '"," or "}" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != '}' and tok.raw != ',')
            break if tok.raw == '}'
            # allow int x[] = {1, 2, 3, };
            break if tok = parser.skipspaces and tok.type == :punct and tok.raw == '}'
            parser.unreadtok tok
            raise tok, 'array is smaller than that' if length and idx >= @length
          end
        end
        ret
      else
        parser.unreadtok tok
        i = super(parser, scope)
        if i.kind_of? CExpression and not i.op and i.rexpr.kind_of? String and @length and i.rexpr.length > @length
          puts tok.exception("initializer is too long (#{i.rexpr.length} for #@length)").message if $VERBOSE
          i.rexpr = i.rexpr[0, @length]
        end
        i
      end
    end

    # this class is a hack to support [1 ... 4] array initializer
    # it stores the effects of subsequent initializers (eg [1 ... 4].toto[48].bla[2 ... 57] = 12)
    # which are later played back on the range
    class AryRecorder
      attr_accessor :log
      def initialize
        @log = []
      end

      def []=(idx, val)
        val = self.class.new if val == []
        @log[idx] = val
      end

      def [](idx)
        @log[idx]
      end

      def playback_idx(i)
        case v = @log[i]
        when self.class; v.playback
        else v
        end
      end

      def playback(ary=[])
        @log.each_with_index { |v, i| ary[i] = playback_idx(i) }
        ary
      end
    end

    # parses a designator+initializer eg '[12] = 4' or '[42].bla = 16' or '[3 ... 8] = 28'
    def parse_initializer_designator(parser, scope, value, idx, root=true)
      # root = true for 1st invocation (x = { 4 }) => immediate value allowed
      #  or false for recursive invocations (x = { .y = 4 }) => need '=' sign before immediate
      if nt = parser.skipspaces and nt.type == :punct and nt.raw == '['
        if not root
          value[idx] ||= []	# AryRecorder may change [] to AryRec.new, can't do v = v[i] ||= []
          value = value[idx]
        end
        raise nt, 'const expected' if not idx = CExpression.parse(parser, scope) or not idx.constant? or not idx = idx.reduce(parser) or not idx.kind_of? ::Integer
        nt = parser.skipspaces
        if nt and nt.type == :punct and nt.raw == '.'	# range
          raise nt || parser, '".." expected' if not nt = parser.skipspaces or nt.type != :punct or nt.raw != '.'
          raise nt || parser,  '"." expected' if not nt = parser.skipspaces or nt.type != :punct or nt.raw != '.'
          raise nt, 'const expected' if not eidx = CExpression.parse(parser, scope) or not eidx.constant? or not eidx = eidx.reduce(parser) or not eidx.kind_of? ::Integer
          raise nt, 'bad range' if eidx < idx
          nt = parser.skipspaces
          realvalue = value
          value = AryRecorder.new
        end
        raise nt || parser, '"]" expected' if not nt or nt.type != :punct or nt.raw != ']'
        raise nt, 'array is smaller than that' if length and (eidx||idx) >= @length
        @type.untypedef.parse_initializer_designator(parser, scope, value, idx, false)
        if eidx
          (idx..eidx).each { |i| realvalue[i] = value.playback_idx(idx) }
          idx = eidx	# next default value = eidx+1 (eg int x[] = { [1 ... 3] = 4, 5 } => x[4] = 5)
        end
      else
        if root
          parser.unreadtok nt
          value[idx] = @type.parse_initializer(parser, scope)
        else
          raise nt || parser, '"=" expected' if not nt or nt.type != :punct or nt.raw != '='
          value[idx] = parse_initializer(parser, scope)
        end
      end
      idx + 1
    end

    # see Union#expand_member_offset
    def expand_member_offset(c_parser, off, str)
      tsz = c_parser.sizeof(@type)
      str << "[#{off/tsz}]"
      if @type.respond_to?(:expand_member_offset)
        @type.expand_member_offset(c_parser, off%tsz, str)
      else
        @type
      end
    end
  end

  class Variable
    include Attributes
    include Typed

    attr_accessor :type
    attr_accessor :initializer	# CExpr	/ Block (for Functions)
    attr_accessor :name
    attr_accessor :storage		# auto register static extern typedef
    attr_accessor :backtrace	# definition backtrace info (the name token)

    def initialize(name=nil, type=nil)
      @name, @type = name, type
    end
  end

  # found in a block's Statements, used to know the initialization order
  # eg { int i; i = 4; struct foo { int k; } toto = {i}; }
  class Declaration
    attr_accessor :var
    def initialize(var)
      @var = var
    end
  end

  class If < Statement
    attr_accessor :test		# expression
    attr_accessor :bthen, :belse	# statements
    def initialize(test, bthen, belse=nil)
      @test = test
      @bthen = bthen
      @belse = belse if belse
    end

    def self.parse(parser, scope, nest)
      tok = nil
      raise tok || self, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
      raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope) or not expr.type.arithmetic?
      raise tok || self, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
      bthen = parser.parse_statement scope, nest
      if tok = parser.skipspaces and tok.type == :string and tok.raw == 'else'
        belse = parser.parse_statement scope, nest
      else
        parser.unreadtok tok
      end

      new expr, bthen, belse
    end
  end
  class For < Statement
    attr_accessor :init, :test, :iter	# CExpressions, init may be Block
    attr_accessor :body
    def initialize(init, test, iter, body)
      @init, @test, @iter, @body = init, test, iter, body
    end

    def self.parse(parser, scope, nest)
      tok = nil
      raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
      init = forscope = Block.new(scope)
      if not parser.parse_definition(forscope)
        forscope = scope
        init = CExpression.parse(parser, forscope)
        raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'
      end
      test = CExpression.parse(parser, forscope)
      raise tok || parser, '";" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ';'
      raise tok, 'bad test expression in for loop' if test and not test.type.arithmetic?
      iter = CExpression.parse(parser, forscope)
      raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

      new init, test, iter, parser.parse_statement(forscope, nest + [:loop])
    end
  end
  class While < Statement
    attr_accessor :test
    attr_accessor :body

    def initialize(test, body)
      @test = test
      @body = body
    end

    def self.parse(parser, scope, nest)
      tok = nil
      raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
      raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope) or not expr.type.arithmetic?
      raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

      new expr, parser.parse_statement(scope, nest + [:loop])
    end
  end
  class DoWhile < While
    def self.parse(parser, scope, nest)
      body = parser.parse_statement(scope, nest + [:loop])
      tok = nil
      raise tok || parser, '"while" expected' if not tok = parser.skipspaces or tok.type != :string or tok.raw != 'while'
      raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
      raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope) or not expr.type.arithmetic?
      raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
      parser.checkstatementend(tok)

      new expr, body
    end
  end
  class Switch < Statement
    attr_accessor :test, :body

    def initialize(test, body)
      @test = test
      @body = body
    end

    def self.parse(parser, scope, nest)
      raise tok || parser, '"(" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '('
      raise tok, 'expr expected' if not expr = CExpression.parse(parser, scope) or not expr.type.integral?
      raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'

      new expr, parser.parse_statement(scope, nest + [:switch])
    end
  end

  class Continue < Statement
  end
  class Break < Statement
  end
  class Goto < Statement
    attr_accessor :target
    def initialize(target)
      @target = target
    end
  end
  class Return < Statement
    attr_accessor :value
    def initialize(value)
      @value = value
    end
  end
  class Label < Statement
    attr_accessor :name
    attr_accessor :statement
    def initialize(name, statement=nil)
      @name, @statement = name, statement
    end
  end
  class Case < Label
    attr_accessor :expr, :exprup	# exprup if range, expr may be 'default'
    def initialize(expr, exprup, statement)
      @expr, @statement = expr, statement
      @exprup = exprup if exprup
    end

    def self.parse(parser, scope, nest)
      raise parser, 'invalid case' if not expr = CExpression.parse(parser, scope) or not expr.constant? or not expr.type.integral?
      raise tok || parser, '":" or "..." expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ':' and tok.raw != '.')
      if tok.raw == '.'
        raise tok || parser, '".." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
        raise tok || parser,  '"." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
        raise tok, 'invalid case range' if not exprup = CExpression.parse(parser, scope) or not exprup.constant? or not exprup.type.integral?
        raise tok || parser, '":" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ':'
      end
      body = parser.parse_statement scope, nest
      new expr, exprup, body
    end
  end

  # inline asm statement
  class Asm < Statement
    include Attributes
    attr_accessor :body		# asm source (::String)
    attr_accessor :output, :input, :clobber	# I/O, gcc-style (::Array)
    attr_accessor :backtrace	# body Token
    attr_accessor :volatile

    def initialize(body, backtrace, output=nil, input=nil, clobber=nil, volatile=nil)
      @body, @backtrace, @output, @input, @clobber, @volatile = body, backtrace, output, input, clobber, volatile
    end

    def self.parse(parser, scope)
      if tok = parser.skipspaces and tok.type == :string and (tok.raw == 'volatile' or tok.raw == '__volatile__')
        volatile = true
        tok = parser.skipspaces
      end
      if not tok or tok.type != :punct or tok.raw != '('
        # detect MS-style inline asm: "__asm .* __asm .*" or "asm { [\s.]* }"
        ftok = tok
        body = ''
        if tok.type == :punct and tok.raw == '{'
          loop do
            raise ftok, 'unterminated asm block' if not tok = parser.lexer.readtok
            break if tok.type == :punct and tok.raw == '}'
            case tok.type
            when :space; body << ' '
            when :eol; body << "\n"
            when :punct; body << tok.raw
            when :quoted; body << CExpression.string_inspect(tok.value)	# concat adjacent c strings
            when :string
              body << \
              case tok.raw
              when 'asm', '__asm', '__asm__'; "\n"
              when '_emit'; 'db'
              else tok.raw
              end
            end
          end
        # allow shell-style heredoc: asm <<EOS\n<asm>\nEOS
        elsif tok.type == :punct and tok.raw == '<'
          raise ftok, 'bad asm heredoc' if not tok = parser.lexer.readtok or tok.type != :punct or tok.raw != '<'
          delimiter = parser.lexer.readtok
          if delimiter.type == :punct and delimiter.raw == '-'
            skipspc = true
            delimiter = parser.lexer.readtok
          end
          raise ftok, 'bad asm heredoc delim' if delimiter.type != :string or not tok = parser.lexer.readtok or tok.type != :eol
          nl = true
          loop do
            raise ftok, 'unterminated heredoc' if not tok = parser.lexer.readtok
            break if nl and tok.raw == delimiter.raw
            raw = tok.raw
            raw = "\n" if skipspc and tok.type == :eol
            body << raw
            nl = (tok.type == :eol and (raw[-1] == ?\n or raw[-1] == ?\r))
          end
        # MS single-instr: asm inc eax;
        # also allow asm "foo bar\nbaz";
        else
          parser.lexer.unreadtok tok
          loop do
            break if not tok = parser.lexer.readtok or tok.type == :eol
            case tok.type
            when :space; body << ' '
            when :punct
              case tok.raw
              when '}'
                parser.lexer.unreadtok tok
                break
              else body << tok.raw
              end
            when :quoted; body << (body.empty? ? tok.value : CExpression.string_inspect(tok.value))	# asm "pop\nret"  VS  asm add al, 'z'
            when :string
              body << \
              case tok.raw
              when 'asm', '__asm', '__asm__'; "\n"
              when '_emit'; 'db'
              else tok.raw
              end
            end
          end
        end
        return new(body, ftok, nil, nil, nil, volatile)
      end
      raise tok || parser, '"(" expected' if not tok or tok.type != :punct or tok.raw != '('
      raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
      body = tok
      ret = new body.value, body
      tok = parser.skipspaces
      raise tok || parser, '":" or ")" expected' if not tok or tok.type != :punct or (tok.raw != ':' and tok.raw != ')')

      if tok.raw == ':'
        ret.output = []
        raise parser if not tok = parser.skipspaces
        while tok.type == :quoted
          type = tok.value
          raise tok, 'expr expected' if not var = CExpression.parse_value(parser, scope)
          ret.output << [type, var]
          raise tok || parser, '":" or "," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')' and tok.raw != ':')
          break if tok.raw == ':' or tok.raw == ')'
          raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
        end
      end
      if tok.raw == ':'
        ret.input = []
        raise parser if not tok = parser.skipspaces
        while tok.type == :quoted
          type = tok.value
          raise tok, 'expr expected' if not var = CExpression.parse_value(parser, scope)
          ret.input << [type, var]
          raise tok || parser, '":" or "," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')' and tok.raw != ':')
          break if tok.raw == ':' or tok.raw == ')'
          raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
        end
      end
      if tok.raw == ':'
        ret.clobber = []
        raise parser if not tok = parser.skipspaces
        while tok.type == :quoted
          ret.clobber << tok.value
          raise tok || parser, '"," or ")" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ',' and tok.raw != ')')
          break if tok.raw == ')'
          raise tok || parser, 'qstring expected' if not tok = parser.skipspaces or tok.type != :quoted
        end
      end
      raise tok || parser, '")" expected' if not tok or tok.type != :punct or tok.raw != ')'
      ret.parse_attributes(parser)
      parser.checkstatementend(tok)
      ret
    end
  end

  class CExpression < Statement
    include Typed

    # may be :,, :., :'->', :funcall (function, [arglist]), :[] (array indexing), nil (cast)
    attr_accessor :op
    # nil/CExpr/Variable/Label/::String( = :quoted/struct member name)/::Integer/::Float/Block
    attr_accessor :lexpr, :rexpr
    # a Type
    attr_accessor :type
    def initialize(l, o, r, t)
      raise "invalid CExpr #{[l, o, r, t].inspect}" if (o and not o.kind_of? ::Symbol) or not t.kind_of? Type
      @lexpr, @op, @rexpr, @type = l, o, r, t
    end

    # overwrites @lexpr @op @rexpr @type from the arg
    def replace(o)
      @lexpr, @op, @rexpr, @type = o.lexpr, o.op, o.rexpr, o.type
      self
    end

    # deep copy of the object
    # recurses only within CExpressions, anything else is copied by reference
    def deep_dup
      n = dup
      n.lexpr = n.lexpr.deep_dup if n.lexpr.kind_of? CExpression
      n.rexpr = n.rexpr.deep_dup if n.rexpr.kind_of? CExpression
      n.rexpr = n.rexpr.map { |e| e.kind_of?(CExpression) ? e.deep_dup : e } if n.rexpr.kind_of? ::Array
      n
    end

    # recursive constructor with automatic type inference
    # e.g. CExpression[foo, :+, [:*, bar]]
    # assumes root args are correctly typed (eg *foo => foo must be a pointer)
    # take care to use [int] with immediates, e.g. CExpression[foo, :+, [2]]
    # CExpr[some_cexpr] returns some_cexpr
    def self.[](*args)
      # sub-arrays in args are to be passed to self.[] recursively (syntaxic sugar)
      splat = lambda { |e| e.kind_of?(::Array) ? self[*e] : e }

      args.shift while args.first == nil	# CExpr[nil, :&, bla] => CExpr[:&, bla]

      case args.length
      when 4
        op = args[1]
        if op == :funcall or op == :'?:'
          x2 = args[2].map { |a| splat[a] } if args[2]
        else
          x2 = splat[args[2]]
        end
        new(splat[args[0]], op, x2, args[3])
      when 3
        op = args[1]
        x1 = splat[args[0]]
        if op == :funcall or op == :'?:'
          x2 = args[2].map { |a| splat[a] } if args[2]
        else
          x2 = splat[args[2]]
        end

        case op
        when :funcall
               rt = x1.type.untypedef
               rt = rt.type.untypedef if rt.pointer?
               new(x1, op, x2, rt.type)
        when :[]; new(x1, op, x2, x1.type.untypedef.type)
        when :+; new(x1, op, x2, (x2.type.pointer? ? x2.type : x1.type))
        when :-; new(x1, op, x2, ((x1.type.pointer? and x2.type.pointer?) ? BaseType.new(:int) : x2.type.pointer? ? x2.type : x1.type))
        when :'&&', :'||', :==, :'!=', :>, :<, :<=, :>=; new(x1, op, x2, BaseType.new(:int))
        when :'.', :'->'
          t = x1.type.untypedef
          t = t.type.untypedef if op == :'->' and x1.type.pointer?
          raise "parse error: #{t} has no member #{x2}" if not t.kind_of? Union or not m = t.findmember(x2)
          new(x1, op, x2, m.type)
        when :'?:'; new(x1, op, x2, x2[0].type)
        when :','; new(x1, op, x2, x2.type)
        else new(x1, op, x2, x1.type)
        end
      when 2
        x0 = splat[args[0]]
        x1 = splat[args[1]]
        x0, x1 = x1, x0 if x0.kind_of? Type
        if x1.kind_of? Type; new(nil, nil, x0, x1)	# (cast)r
        elsif x0 == :*; new(nil, x0, x1, x1.type.untypedef.type)	# *r
        elsif x0 == :& and x1.kind_of? CExpression and x1.type.kind_of? C::Array; new(nil, nil, x1, Pointer.new(x1.type.type))
        elsif x0 == :&; new(nil, x0, x1, Pointer.new(x1.type))	# &r
        elsif x0 == :'!'; new(nil, x0, x1, BaseType.new(:int))	# &r
        elsif x1.kind_of? ::Symbol; new(x0, x1, nil, x0.type)	# l++
        else new(nil, x0, x1, x1.type)	# +r
        end
      when 1
        x = splat[args[0]]
        case x
        when CExpression; x
        when ::Integer; new(nil, nil, x, BaseType.new(:int))	# XXX range => __int64 ?
        when ::Float; new(nil, nil, x, BaseType.new(:double))
        when ::String; new(nil, nil, x, Pointer.new(BaseType.new(:char)))
        else new(nil, nil, x, x.type)
        end
      else raise "parse error CExpr[*#{args.inspect}]"
      end
    end
  end


  class Parser
    # creates a new CParser, parses all top-level statements
    def self.parse(text)
      new.parse text
    end

    # parses the current lexer content (or the text arg) for toplevel definitions
    def parse(text=nil, filename='<unk>', lineno=1)
      @lexer.feed text, filename, lineno if text
      nil while not @lexer.eos? and (parse_definition(@toplevel) or parse_toplevel_statement(@toplevel))
      raise @lexer.readtok || self, 'invalid definition' if not @lexer.eos?
      sanity_checks
      self
    end

    # parses a C file
    def parse_file(file)
      parse(File.read(file), file)
    end

    attr_accessor :lexer, :toplevel, :typesize, :pragma_pack
    attr_accessor :endianness
    attr_accessor :allow_bad_c
    attr_accessor :program
    # allowed arguments: ExeFormat, CPU, Preprocessor, Symbol (for the data model)
    def initialize(*args)
      model = args.grep(Symbol).first || :ilp32
      lexer = args.grep(Preprocessor).first || Preprocessor.new
      @program = args.grep(ExeFormat).first
      cpu = args.grep(CPU).first
      cpu ||= @program.cpu if @program
      @lexer = lexer
      @prev_pragma_callback = @lexer.pragma_callback
      @lexer.pragma_callback = lambda { |tok| parse_pragma_callback(tok) }
      @toplevel = Block.new(nil)
      @unreadtoks = []
      @endianness = cpu ? cpu.endianness : :big
      @typesize = { :void => 1, :__int8 => 1, :__int16 => 2, :__int32 => 4, :__int64 => 8,
        :char => 1, :float => 4, :double => 8, :longdouble => 12 }
      send model
      cpu.tune_cparser(self) if cpu
      @program.tune_cparser(self) if @program
    end

    def ilp16
      @typesize.update :short => 2, :ptr => 2,
        :int => 2, :long => 4, :longlong => 4
    end

    def lp32
      @typesize.update :short => 2, :ptr => 4,
        :int => 2, :long => 4, :longlong => 8
    end
    def ilp32
      @typesize.update :short => 2, :ptr => 4,
        :int => 4, :long => 4, :longlong => 8
    end

    def llp64
      @typesize.update :short => 2, :ptr => 8,
        :int => 4, :long => 4, :longlong => 8
    end
    def lp64
      @typesize.update :short => 2, :ptr => 8,
        :int => 4, :long => 8, :longlong => 8
    end
    def ilp64
      @typesize.update :short => 2, :ptr => 8,
        :int => 8, :long => 8, :longlong => 8
    end

    def parse_pragma_callback(otok)
      case otok.raw
      when 'pack'
        nil while lp = @lexer.readtok and lp.type == :space
        nil while rp = @lexer.readtok and rp.type == :space
        if not rp or rp.type != :punct or rp.raw != ')'
          v1 = rp
          nil while rp = @lexer.readtok and rp.type == :space
        end
        if rp and rp.type == :punct and rp.raw == ','
          nil while v2 = @lexer.readtok and v2.type == :space
          nil while rp = @lexer.readtok and rp.type == :space
        end
        raise otok if not rp or lp.type != :punct or rp.type != :punct or lp.raw != '(' or rp.raw != ')'
        raise otok if (v1 and v1.type != :string) or (v2 and (v2.type != :string or v2.raw =~ /[^\d]/))
        if not v1
          @pragma_pack = nil
        elsif v1.raw == 'push'
          @pragma_pack_stack ||= []
          @pragma_pack_stack << pragma_pack
          @pragma_pack = v2.raw.to_i if v2
          raise v2, 'bad pack value' if pragma_pack == 0
        elsif v1.raw == 'pop'
          @pragma_pack_stack ||= []
          raise v1, 'pack stack empty' if @pragma_pack_stack.empty?
          @pragma_pack = @pragma_pack_stack.pop
          @pragma_pack = v2.raw.to_i if v2 and v2.raw	# #pragma pack(pop, 4) => pop stack, but use 4 as pack value (imho)
          raise v2, 'bad pack value' if @pragma_pack == 0
        elsif v1.raw =~ /^\d+$/
          raise v2, '2nd arg unexpected' if v2
          @pragma_pack = v1.raw.to_i
          raise v1, 'bad pack value' if @pragma_pack == 0
        else raise otok
        end
        # the caller checks for :eol
      when 'warning'
        if $DEBUG
          @prev_pragma_callback[otok]
        else
          # silent discard
          nil while tok = @lexer.readtok_nopp and tok.type != :eol
          @lexer.unreadtok tok
        end
      when 'prepare_visualstudio'
        prepare_visualstudio
      when 'prepare_gcc'
        prepare_gcc
      when 'data_model'	# XXX use carefully, should be the very first thing parsed
        nil while lp = @lexer.readtok and lp.type == :space
        if lp.type != :string or lp.raw !~ /^s?[il]?lp(16|32|64)$/ or not respond_to? lp.raw
          raise lp, "invalid data model (use lp32/lp64/llp64/ilp64)"
        else
          send lp.raw
        end
      else @prev_pragma_callback[otok]
      end
    end

    def prepare_visualstudio
      @lexer.define_weak('_WIN32')
      @lexer.define_weak('_WIN32_WINNT', 0x500)
      @lexer.define_weak('_INTEGRAL_MAX_BITS', 64)
      @lexer.define_weak('__w64')
      @lexer.define_weak('_cdecl', '__cdecl')	# typo ? seen in winreg.h
      @lexer.define_weak('_fastcall', '__fastcall')	# typo ? seen in ntddk.h
      @lexer.define_weak('_MSC_VER', 1300)	# handle '#pragma once' and _declspec(noreturn)
      @lexer.define_weak('__forceinline', '__inline')
      @lexer.define_weak('__ptr32')	# needed with msc_ver 1300, don't understand their use
      @lexer.define_weak('__ptr64')
    end

    def prepare_gcc
      @lexer.define_weak('__GNUC__', 2)	# otherwise __attribute__ is defined to void..
      @lexer.define_weak('__STDC__')
      @lexer.define_weak('__const', 'const')
      @lexer.define_weak('__signed', 'signed')
      @lexer.define_weak('__signed__', 'signed')
      @lexer.define_weak('__volatile', 'volatile')
      if not @lexer.definition['__builtin_constant_p']
        # magic macro to check if its arg is an immediate value
        @lexer.define_weak('__builtin_constant_p', '0')
        @lexer.definition['__builtin_constant_p'].args = [Preprocessor::Token.new([])]
      end
      @lexer.nodefine_strong('alloca')		# TODO __builtin_alloca
      @lexer.hooked_include['stddef.h'] = <<EOH
/* simplified, define all at first invocation. may break things... */
#undef __need_ptrdiff_t
#undef __need_size_t
#undef __need_wint_t
#undef __need_wchar_t
#undef __need_NULL
#undef NULL
#if !defined (_STDDEF_H)
#define _STDDEF_H
#define __PTRDIFF_TYPE__ long int
typedef __PTRDIFF_TYPE__ ptrdiff_t;
#define __SIZE_TYPE__ long unsigned int
typedef __SIZE_TYPE__ size_t;
#define __WINT_TYPE__ unsigned int
typedef __WINT_TYPE__ wint_t;
#define __WCHAR_TYPE__ int
typedef __WCHAR_TYPE__ wchar_t;
#define NULL 0
#define offsetof(TYPE, MEMBER) __builtin_offsetof (TYPE, MEMBER)
#endif
EOH
      # TODO va_args
      @lexer.hooked_include['stdarg.h'] = <<EOH
// TODO
typedef void* __gnuc_va_list;
/*
typedef void* va_list;
#define va_start(v, l)
#define va_end(v)
#define va_arg(v, l)
#define va_copy(d, s)
*/
EOH
      @lexer.hooked_include['limits.h'] = <<EOH
#define CHAR_BIT      8
#define SCHAR_MIN     (-128)
#define SCHAR_MAX     127
#define UCHAR_MAX     255
#ifdef __CHAR_UNSIGNED__
#   define CHAR_MIN     0
#   define CHAR_MAX     UCHAR_MAX
#else
#   define CHAR_MIN     SCHAR_MIN
#   define CHAR_MAX     SCHAR_MAX
#endif
#define UINT_MAX       #{(1 << (8*@typesize[:int]))-1}U
#define INT_MAX       (UINT_MAX >> 1)
#define INT_MIN       (-INT_MAX - 1)
#define ULONG_MAX       #{(1 << (8*@typesize[:long]))-1}UL
#define LONG_MAX       (ULONG_MAX >> 1L)
#define LONG_MIN       (-LONG_MAX - 1L)
EOH
    end

    # C sanity checks
    def sanity_checks
      return if not $VERBOSE
      #  TODO
    end

    # checks that the types are compatible (variable predeclaration, function argument..)
    # strict = false for func call/assignment (eg char compatible with int -- but int is incompatible with char)
    # output warnings only
    def check_compatible_type(tok, oldtype, newtype, strict = false, checked = [])
      return if not $VERBOSE
      oldtype = oldtype.untypedef
      newtype = newtype.untypedef
      oldtype = BaseType.new(:int) if oldtype.kind_of? Enum
      newtype = BaseType.new(:int) if newtype.kind_of? Enum

      puts tok.exception('type qualifier mismatch').message if oldtype.qualifier.to_a.uniq.length > newtype.qualifier.to_a.uniq.length

      # avoid infinite recursion
      return if checked.include? oldtype
      checked = checked + [oldtype]

        begin
      case newtype
      when Function
        raise tok, 'type error' if not oldtype.kind_of? Function
        check_compatible_type tok, oldtype.type, newtype.type, strict, checked
        if oldtype.args and newtype.args
          if oldtype.args.length != newtype.args.length or
              oldtype.varargs != newtype.varargs
            raise tok, 'type error'
          end
          oldtype.args.zip(newtype.args) { |oa, na|
            # begin ; rescue ParseError: raise $!.message + "in parameter #{oa.name}" end
            check_compatible_type tok, oa.type, na.type, strict, checked
          }
        end
      when Pointer
        if oldtype.kind_of? BaseType and oldtype.integral?
          puts tok.exception('making pointer from integer without a cast').message
          return
        end
        raise tok, 'type error' if not oldtype.kind_of? Pointer
        hasvoid = true if (t = newtype.type.untypedef).kind_of? BaseType and t.name == :void
        hasvoid = true if (t = oldtype.type.untypedef).kind_of? BaseType and t.name == :void	# struct foo *f = NULL;
        if strict and not hasvoid
          check_compatible_type tok, oldtype.type, newtype.type, strict, checked
        end
      when Union
        raise tok, 'type error' if not oldtype.class == newtype.class
        if oldtype.members and newtype.members
          if oldtype.members.length != newtype.members.length
            raise tok, 'bad member count'
          end
          oldtype.members.zip(newtype.members) { |om, nm|
            # raise tok if om.name and nm.name and om.name != nm.name # don't care
            check_compatible_type tok, om.type, nm.type, strict, checked
          }
        end
      when BaseType
        raise tok, 'type error' if not oldtype.kind_of? BaseType
        if strict
          if oldtype.name != newtype.name or
          oldtype.specifier != newtype.specifier
            raise tok, 'type error'
          end
        else
          raise tok, 'type error' if @typesize[newtype.name] == 0 and @typesize[oldtype.name] > 0
          puts tok.exception('type size mismatch, may lose bits').message if @typesize[oldtype.name] > @typesize[newtype.name]
          puts tok.exception('sign mismatch').message if oldtype.specifier != newtype.specifier and @typesize[newtype.name] == @typesize[oldtype.name]
        end
      end
        rescue ParseError
      raise $! if checked.length != 1	# bubble up
      oname = (oldtype.to_s rescue oldtype.class.name)
      nname = (newtype.to_s rescue newtype.class.name)
      puts $!.message + " incompatible type #{oname} to #{nname}"
        end
    end

    # allows 'raise self'
    def exception(msg='EOF unexpected')
      @lexer.exception msg
    end

    # reads a token, convert 'L"foo"' to a :quoted
    def readtok_longstr
      if t = @lexer.readtok and t.type == :string and t.raw == 'L' and
      nt = @lexer.readtok and nt.type == :quoted and nt.raw[0] == ?"
        nt.raw[0, 0] = 'L'
        nt
      elsif t and t.type == :punct and t.raw == '/' and
      # nt has not been read
      nt = @lexer.readtok and nt.type == :punct and nt.raw == '/'
        # windows.h has a #define some_type_name /##/, and VS interprets this as a comment..
        puts @lexer.exception('#defined //').message if $VERBOSE
        t = @lexer.readtok while t and t.type != :eol
        t
      else
        @lexer.unreadtok nt
        t
      end
    end
    private :readtok_longstr

    # reads a token from self.lexer
    # concatenates strings, merges spaces/eol to ' ', handles wchar strings, allows $@_ in :string
    def readtok
      if not t = @unreadtoks.pop
        return if not t = readtok_longstr
        case t.type
        when :space, :eol
          # merge consecutive :space/:eol
          t = t.dup
          t.type = :space
          t.raw = ' '
          nil while nt = @lexer.readtok and (nt.type == :eol or nt.type == :space)
          @lexer.unreadtok nt

        when :quoted
          # merge consecutive :quoted
          t = t.dup
          while nt = readtok_longstr
            case nt.type
            when :quoted
              if t.raw[0] == ?" and nt.raw[0, 2] == 'L"'
                # ensure wide prefix is set
                t.raw[0, 0] = 'L'
              end
              t.raw << ' ' << nt.raw
              t.value << nt.value
            when :space, :eol
            else break
            end
          end
          @lexer.unreadtok nt
        else
          if (t.type == :punct and (t.raw == '_' or t.raw == '@' or t.raw == '$')) or t.type == :string
            t = t.dup
            t.type = :string
            nt = nil
            t.raw << nt.raw while nt = @lexer.readtok and ((nt.type == :punct and (nt.raw == '_' or nt.raw == '@' or nt.raw == '$')) or nt.type == :string)
            @lexer.unreadtok nt
          end
        end
      end
      t
    end

    def eos?
      @unreadtoks.empty? and @lexer.eos?
    end

    def unreadtok(tok)
      @unreadtoks << tok if tok
    end

    # returns the next non-space/non-eol token
    def skipspaces
      nil while t = readtok and t.type == :space
      t
    end

    # checks that we are at the end of a statement, ie an ';' character (consumed), or a '}' (not consumed)
    # otherwise, raise either the given token or self.
    def checkstatementend(tok=nil)
      raise tok || self, '";" expected' if not tok = skipspaces or tok.type != :punct or (tok.raw != ';' and tok.raw != '}')
      unreadtok tok if tok.raw == '}'
    end

    # returns the size of a type in bytes
    def sizeof(var, type=nil)
      var, type = nil, var if var.kind_of? Type and not type
      type ||= var.type
      # XXX double-check class apparition order ('when' checks inheritance)
      case type
      when Array
        case type.length
        when nil
          if var.kind_of? CExpression and not var.lexpr and not var.op and var.rexpr.kind_of? Variable
            var = var.rexpr
          end
          raise self, 'unknown array size' if not var.kind_of? Variable or not var.initializer
          init = var.initializer
          init = init.rexpr if init.kind_of? C::CExpression and not init.op and init.rexpr.kind_of? ::String
          case init
          when ::String; sizeof(nil, type.type) * (init.length + 1)
          when ::Array
            v = init.compact.first
            v ? (sizeof(nil, type.type) * init.length) : 0
          else sizeof(init)
          end
        when ::Integer; type.length * sizeof(type.type)
        when CExpression
          len = type.length.reduce(self)
          raise self, 'unknown array size' if not len.kind_of? ::Integer
          len * sizeof(type)
        else raise self, 'unknown array size'
        end
      when Pointer
        if var.kind_of? CExpression and not var.op and var.rexpr.kind_of? ::String
          # sizeof("lolz") => 5
          sizeof(nil, type.type) * (var.rexpr.length + 1)
        else
          @typesize[:ptr]
        end
      when Function
        # raise
        1	# gcc
      when BaseType
        @typesize[type.name]
      when Enum
        @typesize[:int]
      when Struct
        raise self, "unknown structure size #{type.name}" if not type.members
        al = type.align(self)
        al = 1 if (var.kind_of?(Attributes) and var.has_attribute('sizeof_packed')) or type.has_attribute('sizeof_packed')
        lm = type.members.last
        lm ? (type.offsetof(self, lm) + sizeof(lm) + al - 1) / al * al : 0
      when Union
        raise self, "unknown structure size #{type.name}" if not type.members
        type.members.map { |m| sizeof(m) }.max || 0
      when TypeDef
        sizeof(var, type.type)
      end
    end

    # parses variable/function definition/declaration/initialization
    # populates scope.symbols and scope.struct
    # raises on redefinitions
    # returns false if no definition found
    def parse_definition(scope)
      return false if not basetype = Variable.parse_type(self, scope, true)

      # check struct predeclaration
      tok = skipspaces
      if tok and tok.type == :punct and tok.raw == ';' and basetype.type and
          (basetype.type.kind_of? Union or basetype.type.kind_of? Enum)
        return true
      else unreadtok tok
      end

      nofunc = false
      loop do
        var = basetype.dup
        var.parse_declarator(self, scope)

        raise var.backtrace if not var.name	# barrel roll

        if prev = scope.symbol[var.name]
          if prev.kind_of? TypeDef and var.storage == :typedef
            check_compatible_type(var.backtrace, prev.type, var.type, true)
            # windows.h redefines many typedefs with the same definition
            puts "redefining typedef #{var.name}" if $VERBOSE
            var = prev
          elsif not prev.kind_of?(Variable) or
              prev.initializer or
              (prev.storage != :extern and prev.storage != var.storage) or
              (scope != @toplevel and prev.storage != :static)
            if prev.kind_of? ::Integer	# enum value
              prev = (scope.struct.values.grep(Enum) + scope.anonymous_enums.to_a).find { |e| e.members.index(prev) }
            end
            raise var.backtrace, "redefinition, previous is #{prev.backtrace.exception(nil).message rescue :unknown}"
          else
            check_compatible_type var.backtrace, prev.type, var.type, true
            (var.attributes ||= []).concat prev.attributes if prev.attributes
          end
        elsif var.storage == :typedef
          attrs = var.attributes
          var = TypeDef.new var.name, var.type, var.backtrace
          var.attributes = attrs if attrs
        end
        scope.statements << Declaration.new(var) unless var.kind_of? TypeDef

        raise tok || self, 'punctuation expected' if not tok = skipspaces or (tok.type != :punct and not %w[asm __asm __asm__].include? tok.raw)

        case tok.raw
        when '{'
          # function body
          raise tok if nofunc or not var.kind_of? Variable or not var.type.kind_of? Function
          scope.symbol[var.name] = var
          body = var.initializer = Block.new(scope)
          var.type.args ||= []
          var.type.args.each { |v|
            # put func parameters in func body scope
            # arg redefinition is checked in parse_declarator
            if not v.name
              puts "unnamed argument in definition of #{var.name}" if $DEBUG
              next	# should raise to be compliant
            end
            body.symbol[v.name] = v	# XXX will need special check in stack allocator
          }

          loop do
            raise tok || self, var.backtrace.exception('"}" expected for end of function') if not tok = skipspaces
            break if tok.type == :punct and tok.raw == '}'
            unreadtok tok
            if not parse_definition(body)
              body.statements << parse_statement(body, [var.type.type])
            end
          end
          if $VERBOSE and not body.statements.last.kind_of? Return and not body.statements.last.kind_of? Asm
            puts tok.exception('missing function return value').message if not var.type.type.untypedef.kind_of? BaseType or var.type.type.untypedef.name != :void
          end
          break
        when 'asm', '__asm', '__asm__'
          # GCC function redirection
          # void foo(void) __asm__("bar");  =>  when code uses 'foo', silently redirect to 'bar' instead
          raise tok if nofunc or not var.kind_of? Variable or not var.type.kind_of? Function
          # most of the time, 'bar' is not defined anywhere, so we support it only
          # to allow parsing of headers using it, hoping noone will actually use them
          unused = Asm.parse(self, scope)
          puts "unsupported gcc-style __asm__ function redirect #{var.name.inspect} => #{unused.body.inspect}" if $VERBOSE
          break
        when '='
          # variable initialization
          raise tok, '"{" or ";" expected' if var.type.kind_of? Function
          raise tok, 'cannot initialize extern variable' if var.storage == :extern
          scope.symbol[var.name] = var	# allow initializer to reference var, eg 'void *ptr = &ptr;'
          var.initializer = var.type.parse_initializer(self, scope)
          if var.initializer.kind_of?(CExpression) and (scope == @toplevel or var.storage == :static)
            raise tok, "initializer for static #{var.name} is not constant" if not var.initializer.constant?
          end
          reference_value = lambda { |e, v|
            found = false
            case e
            when Variable; found = true if e == v
            when CExpression; e.walk { |ee| found ||= reference_value[ee, v] } if e.op != :& or e.lexpr
            end
            found
          }
          raise tok, "initializer for #{var.name} is not constant (selfreference)" if reference_value[var.initializer, var]
          raise tok || self, '"," or ";" expected' if not tok = skipspaces or tok.type != :punct
        else
          scope.symbol[var.name] = var
        end

        case tok.raw
        when ','; nofunc = true
        when ';'; break
        when '}'; unreadtok(tok); break
        else raise tok, '";" or "," expected'
        end
      end
      true
    end

    # parses toplevel statements, return nil if none found
    # toplevel statements are ';' and 'asm <..>'
    def parse_toplevel_statement(scope)
      if tok = skipspaces and tok.type == :punct and tok.raw == ';'
        true
      elsif tok and tok.type == :punct and tok.raw == '{'
        raise tok || self, '"}" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != '}'
        true
      elsif tok and tok.type == :string and %w[asm __asm __asm__].include? tok.raw
        scope.statements << Asm.parse(self, scope)
        true
      end
    end

    # returns a statement or raise
    def parse_statement(scope, nest)
      raise self, 'statement expected' if not tok = skipspaces

      if tok.type == :punct and tok.raw == '{'
        body = Block.new scope
        loop do
          raise tok || self, '"}" expected' if not tok = skipspaces
          break if tok.type == :punct and tok.raw == '}'
          unreadtok tok
          if not parse_definition(body)
            body.statements << parse_statement(body, nest)
          end
        end
        return body
      elsif tok.type == :punct and tok.raw == ';'
        return Block.new(scope)
      elsif tok.type != :string
        unreadtok tok
        raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
        checkstatementend(tok)

        if $VERBOSE and not nest.include?(:expression) and (expr.op or not expr.type.untypedef.kind_of? BaseType or expr.type.untypedef.name != :void) and CExpression.constant?(expr)
          puts tok.exception("statement with no effect : #{expr}").message
        end
        return expr
      end

      case tok.raw
      when 'if'
        If.parse      self, scope, nest
      when 'while'
        While.parse   self, scope, nest
      when 'do'
        DoWhile.parse self, scope, nest
      when 'for'
        For.parse     self, scope, nest
      when 'switch'
        Switch.parse  self, scope, nest
      when 'goto'
        raise tok || self, 'label expected' if not tok = skipspaces or tok.type != :string
        name = tok.raw
        checkstatementend(tok)
        Goto.new name
      when 'return'
        expr = CExpression.parse(self, scope)	# nil allowed
        raise tok || self, "cannot return #{expr} in function returning void" if expr and nest[0].kind_of?(Type) and nest[0].void?
        p, i = nest[0].pointer?, nest[0].integral? if expr
        r = expr.reduce(self) if p or i
        if (not p and not i) or (i and not r.kind_of? ::Integer) or (p and r != 0)
          check_compatible_type(tok, (expr ? expr.type : BaseType.new(:void)), nest[0])
        end
        checkstatementend(tok)
        Return.new expr
      when 'case'
        raise tok, 'case out of switch' if not nest.include? :switch
        Case.parse    self, scope, nest
      when 'default'
        raise tok || self, '":" expected' if not tok = skipspaces or tok.type != :punct or tok.raw != ':'
        raise tok, 'case out of switch' if not nest.include? :switch
        Case.new 'default', nil, parse_statement(scope, nest)
      when 'continue'
        checkstatementend(tok)
        raise tok, 'continue out of loop' if not nest.include? :loop
        Continue.new
      when 'break'
        checkstatementend(tok)
        raise tok, 'break out of loop' if not nest.include? :loop and not nest.include? :switch
        Break.new
      when 'asm', '__asm', '__asm__'
        Asm.parse self, scope
      else
        if ntok = skipspaces and ntok.type == :punct and ntok.raw == ':'
          begin
            st = parse_statement(scope, nest)
          rescue ParseError
            puts "label without statement, #{$!.message}" if $VERBOSE
          end
          Label.new tok.raw, st
        else
          unreadtok ntok
          unreadtok tok
          raise tok, 'expr expected' if not expr = CExpression.parse(self, scope)
          checkstatementend(tok)

          if $VERBOSE and not nest.include?(:expression) and (expr.op or not expr.type.untypedef.kind_of? BaseType or expr.type.untypedef.name != :void) and CExpression.constant?(expr)
            puts tok.exception("statement with no effect : #{expr}").message
          end
          expr
        end
      end
    end

    # check if a macro definition has a numeric value
    # returns this value or nil
    def macro_numeric(m)
      d = @lexer.definition[m]
      return if not d.kind_of? Preprocessor::Macro or d.args or d.varargs
      # filter metasm-defined vars (eg __PE__ / _M_IX86)
      return if not d.name or not bt = d.name.backtrace or (bt[0][0] != ?" and bt[0][0] != ?<)
      raise 'cannot macro_numeric with unparsed data' if not eos?
      @lexer.feed m
      if e = CExpression.parse(self, Block.new(@toplevel)) and eos?
        v = e.reduce(self)
        return v if v.kind_of? ::Numeric
      end
      readtok until eos?
      nil
    rescue ParseError
      readtok until eos?
      nil
    end

    # returns all numeric constants defined with their value, either macros or enums
    # for enums, also return the enum name
    def numeric_constants
      ret = []
      # macros
      @lexer.definition.each_key { |k|
        if v = macro_numeric(k)
          ret << [k, v]
        end
      }
      # enums
      seen_enum = {}
      @toplevel.struct.each { |k, v|
        if v.kind_of?(Enum)
          v.members.each { |kk, vv|
            ret << [kk, vv, k]
            seen_enum[kk] = true
          }
        end
      }
      @toplevel.symbol.each { |k, v|
        ret << [k, v] if v.kind_of?(::Numeric) and not seen_enum[k]
      }
      ret
    end
  end

  class Variable
    # parses a variable basetype/qualifier/(storage if allow_value), returns a new variable of this type
    # populates scope.struct
    def self.parse_type(parser, scope, allow_value = false)
      var = new
      qualifier = []
      tok = nil
      loop do
        var.parse_attributes(parser, true)
        break if not tok = parser.skipspaces
        if tok.type != :string
          parser.unreadtok tok
          break
        end

        case tok.raw
        when 'const', 'volatile'
          qualifier << tok.raw.to_sym
          next
        when 'register', 'auto', 'static', 'typedef', 'extern'
          raise tok, 'storage specifier not allowed here' if not allow_value
          raise tok, 'multiple storage class' if var.storage
          var.storage = tok.raw.to_sym
          next
        when 'struct'
          var.type = Struct.new
          var.type.pack = parser.pragma_pack if parser.pragma_pack
          var.parse_type_struct(parser, scope)
        when 'union'
          var.type = Union.new
          var.parse_type_struct(parser, scope)
        when 'enum'
          var.type = Enum.new
          var.parse_type_struct(parser, scope)
        when 'typeof'
          if ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '('
            # check type
            if v = parse_type(parser, scope)
              v.parse_declarator(parser, scope)
              raise tok if v.name != false
              raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            else
              raise tok, 'expr expected' if not v = CExpression.parse(parser, scope)
              raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            end
          else
            parser.unreadtok ntok
            raise tok, 'expr expected' if not v = CExpression.parse_value(parser, scope)
          end
          var.type = v.type # TypeDef.new('typeof', v.type, tok)
        when 'long', 'short', 'signed', 'unsigned', 'int', 'char', 'float', 'double',
            'void', '__int8', '__int16', '__int32', '__int64',
            'intptr_t', 'uintptr_t'
          parser.unreadtok tok
          var.parse_type_base(parser, scope)
        else
          if type = scope.symbol_ancestors[tok.raw] and type.kind_of? TypeDef
            var.type = type.dup
          else
            parser.unreadtok tok
          end
        end

        break
      end

      if not var.type
        raise tok || parser, 'bad type name' if not qualifier.empty? or var.storage
        nil
      else
        var.type.qualifier = var.type.qualifier.to_a | qualifier if not qualifier.empty?
        var.type.parse_attributes(parser, true)
        var
      end
    end

    # parses a structure/union/enum declaration
    def parse_type_struct(parser, scope)
      @type.parse_attributes(parser)
      if tok = parser.skipspaces and tok.type == :punct and tok.raw == '{'
        # anonymous struct, ok
        @type.backtrace = tok
        if @type.kind_of? Enum
          (scope.anonymous_enums ||= []) << @type
        end
      elsif tok and tok.type == :string
        name = tok.raw
        raise tok, 'bad struct name' if Keyword[name] or (?0..?9).include?(name[0])
        @type.backtrace = tok
        @type.name = name
        @type.parse_attributes(parser)
        raise parser if not ntok = parser.skipspaces
        if ntok.type != :punct or ntok.raw != '{'
          raise tok, "struct/union confusion" if scope.struct[name] and scope.struct[name].class != @type.class
          # variable declaration
          parser.unreadtok ntok
          if ntok.type == :punct and ntok.raw == ';'
            # struct predeclaration
            # allow redefinition
            @type = scope.struct[name] ||= @type
          else
            # check that the structure exists
            struct = scope.struct_ancestors[name]
            # allow incomplete types, usage as var type will raise later
            struct = scope.struct[name] = @type if not struct
            raise tok, 'unknown struct' if struct.class != @type.class
            (struct.attributes ||= []).concat @type.attributes if @type.attributes
            (struct.qualifier  ||= []).concat @type.qualifier  if @type.qualifier	# XXX const struct foo bar => bar is const, not foo...
            @type = struct
          end
          return
        end
        if scope.struct[name] and scope.struct[name].members
          # redefinition of an existing struct, save for later comparison
          oldstruct = scope.struct[name]
          raise tok, "struct/union confusion" if oldstruct.class != @type.class
        elsif struct = scope.struct[name]
          raise tok, "struct/union confusion" if struct.class != @type.class
          (struct.attributes ||= []).concat @type.attributes if @type.attributes
          (struct.qualifier  ||= []).concat @type.qualifier  if @type.qualifier
          struct.backtrace = @type.backtrace
          struct.name = @type.name
          @type = struct
        else
          scope.struct[name] = @type
        end
      else
        raise tok || parser, 'struct name or "{" expected'
      end

      @type.parse_members(parser, scope)

      if oldstruct
        if not @type.compare_deep(oldstruct)
          raise tok, "conflicting struct redefinition (old at #{oldstruct.backtrace.exception(nil).message rescue :unknown})"
        end
        @type = oldstruct
      end
    end

    # parses int/long int/long long/double etc
    def parse_type_base(parser, scope)
      specifier = []
      qualifier = []
      name = :int
      tok = nil
      loop do
        if not tok = parser.skipspaces
          raise parser if specifier.empty?
          break
        end
        if tok.type != :string
          parser.unreadtok tok
          break
        end
        case tok.raw
        when 'const', 'volatile'
          qualifier << tok.raw.to_sym
        when 'long', 'short', 'signed', 'unsigned'
          specifier << tok.raw.to_sym
        when 'int', 'char', 'void', 'float', 'double', '__int8', '__int16', '__int32', '__int64'
          name = tok.raw.to_sym
          break
        when 'intptr_t', 'uintptr_t'
          name = :ptr
          specifier << :unsigned if tok.raw == 'uintptr_t'
          break
        else
          parser.unreadtok tok
          break
        end
      end

      case name
      when :double	# long double
        if specifier == [:long]
          name = :longdouble
          specifier.clear
        elsif not specifier.empty?
          raise tok || parser, 'invalid specifier list'
        end
      when :int	# short, long, long long X signed, unsigned
        # Array#count not available on old ruby (eg 1.8.4), so use ary.len - (ary-stuff).len
        specifier = specifier - [:long] + [:longlong] if specifier.length - (specifier-[:long]).length == 2
        if specifier.length - (specifier-[:signed, :unsigned]).length > 1 or specifier.length - (specifier-[:short, :long, :longlong]).length > 1
          raise tok || parser, 'invalid specifier list'
        else
          name = (specifier & [:longlong, :long, :short])[0] || :int
          specifier -= [:longlong, :long, :short]
        end
        specifier.delete :signed	# default
      when :char	# signed, unsigned
        # signed char != char and unsigned char != char
        if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long]).length > 0
          raise tok || parser, 'invalid specifier list'
        end
      when :__int8, :__int16, :__int32, :__int64, :ptr
        if (specifier & [:signed, :unsigned]).length > 1 or (specifier & [:short, :long]).length > 0
          raise tok || parser, 'invalid specifier list'
        end
        specifier.delete :signed	# default
      else		# none
        raise tok || parser, 'invalid type' if not specifier.empty?
      end

      @type = BaseType.new(name, *specifier)
      @type.qualifier = qualifier if not qualifier.empty?
    end

    # updates @type and @name, parses pointer/arrays/function declarations
    # parses anonymous declarators (@name will be false)
    # the caller is responsible for detecting redefinitions
    # scope used only in CExpression.parse for array sizes and function prototype argument types
    # rec for internal use only
    def parse_declarator(parser, scope, rec = false)
      parse_attributes(parser, true)
      tok = parser.skipspaces
      # read upto name
      if tok and tok.type == :punct and tok.raw == '*'
        ptr = Pointer.new
        ptr.parse_attributes(parser)
        while ntok = parser.skipspaces and ntok.type == :string
          case ntok.raw
          when 'const', 'volatile'
            (ptr.qualifier ||= []) << ntok.raw.to_sym
            ptr.parse_attributes(parser)
          else break
          end
        end
        parser.unreadtok ntok
        parse_declarator(parser, scope, true)
        t = self
        t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
        ptr.type = t.type
        t.type = ptr
        if t.kind_of? Function and ptr.attributes
          @attributes ||= []
          @attributes |= ptr.attributes
          ptr.attributes = nil
        end
        return
      elsif tok and tok.type == :punct and tok.raw == '('
        parse_declarator(parser, scope, true)
        raise tok || parser, '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
      elsif tok and tok.type == :string
        case tok.raw
        when 'const', 'volatile'
          (@type.qualifier ||= []) << tok.raw.to_sym
          return parse_declarator(parser, scope, rec)
        when 'register', 'auto', 'static', 'typedef', 'extern'
          raise tok, 'multiple storage class' if storage
          @storage = tok.raw.to_sym
          puts tok.exception('misplaced storage specifier').message if $VERBOSE
          return parse_declarator(parser, scope, rec)
        end
        raise tok if name or name == false
        raise tok, 'bad var name' if Keyword[tok.raw] or (?0..?9).include?(tok.raw[0])
        @name = tok.raw
        @backtrace = tok
        parse_attributes(parser, true)
      else
        # unnamed
        raise tok || parser if name or name == false
        @name = false
        @backtrace = tok
        parser.unreadtok tok
        parse_attributes(parser, true)
      end
      parse_declarator_postfix(parser, scope)
      if not rec
        raise @backtrace, 'void type is invalid' if name and (t = @type.untypedef).kind_of? BaseType and
            t.name == :void and storage != :typedef
        raise @backtrace, "incomplete type #{@type.name}" if (@type.kind_of? Union or @type.kind_of? Enum) and
            not @type.members and storage != :typedef and storage != :extern	# gcc uses an undefined extern struct just to cast it later (_IO_FILE_plus)
      end
    end

    # parses array/function type
    def parse_declarator_postfix(parser, scope)
      if tok = parser.skipspaces and tok.type == :punct and tok.raw == '['
        # array indexing
        idx = CExpression.parse(parser, scope)	# may be nil
        if idx and (scope == parser.toplevel or storage == :static)
          raise tok, 'array size is not constant' if not idx.constant?
          idx = idx.reduce(parser)
        elsif idx and nidx = idx.reduce(parser) and nidx.kind_of? ::Integer
          idx = nidx
        end
        t = self
        t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
        t.type = Array.new t.type
        t.type.length = idx
        raise tok || parser, '"]" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ']'
        parse_attributes(parser)	# should be type.attrs, but this is should be more compiler-compatible
      elsif tok and tok.type == :punct and tok.raw == '('
        # function prototype
        # void __attribute__((noreturn)) func() => attribute belongs to func
        if @type and @type.attributes
          @attributes ||= []
          @attributes |= @type.attributes
          @type.attributes = nil
        end
        t = self
        t = t.type while t.type and (t.type.kind_of?(Pointer) or t.type.kind_of?(Function))
        t.type = Function.new t.type
        if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
          parser.unreadtok tok
          t.type.args = []
          oldstyle = false	# int func(a, b) int a; double b; { stuff; }
          loop do
            raise parser if not tok = parser.skipspaces
            if tok.type == :punct and tok.raw == '.'	# variadic function
              raise parser, '".." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
              raise parser,  '"." expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '.'
              raise parser,  '")" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ')'
              t.type.varargs = true
              break
            elsif tok.type == :string and tok.raw == 'register'
              storage = :register
            else
              parser.unreadtok tok
            end

            if oldstyle or not v = Variable.parse_type(parser, scope)
              raise tok if not @name	# no oldstyle in casts
              tok = parser.skipspaces
              oldstyle ||= [tok]	# arg to raise() later
              oldstyle << tok.raw
            else
              v.storage = storage if storage
              v.parse_declarator(parser, scope)
              v.type = Pointer.new(v.type.type) if v.type.kind_of? Array
              v.type = Pointer.new(v.type) if v.type.kind_of? Function

              t.type.args << v if not v.type.untypedef.kind_of? BaseType or v.type.untypedef.name != :void
            end

            if tok = parser.skipspaces and tok.type == :punct and tok.raw == ','
              raise tok, '")" expected' if v and t.type.args.last != v	# last arg of type :void
            elsif tok and tok.type == :punct and tok.raw == ')'
              break
            else raise tok || parser, '"," or ")" expected'
            end
          end
          if oldstyle
            parse_attributes(parser, true)
            ra = oldstyle.shift
            while t.type.args.compact.length != oldstyle.length
              raise ra, "invalid prototype" if not vb = Variable.parse_type(parser, scope)
              loop do
                v = vb.dup
                v.parse_declarator(parser, scope)
                v.type = Pointer.new(v.type.type) if v.type.kind_of? Array
                v.type = Pointer.new(v.type) if v.type.kind_of? Function
                raise parser, "unknown arg #{v.name.inspect}" if not i = oldstyle.index(v.name)
                t.type.args[i] = v
                raise parser, '"," or ";" expected' if not tok = parser.skipspaces or tok.type != :punct or (tok.raw != ';' and tok.raw != ',')
                break if tok.raw == ';'
              end
            end
            parse_attributes(parser, true)
            raise parser, '"{" expected' if not tok = parser.skipspaces or tok.type != :punct or tok.raw != '{'
            parser.unreadtok tok
          end
          namedargs = t.type.args.map { |a| a.name }.compact - [false]
          raise tok, "duplicate argument name #{namedargs.find { |a| namedargs.index(a) != namedargs.rindex(a) }.inspect}" if namedargs.length != namedargs.uniq.length
        end
        parse_attributes(parser, true)	# should be type.attrs, but this should be more existing-compiler-compatible
      else
        parser.unreadtok tok
        return
      end
      parse_declarator_postfix(parser, scope)
    end
  end

  class Variable
    def ===(o)
      self == o or (o.class == CExpression and not o.op and o.rexpr == self)
    end
  end

  class CExpression
    def self.lvalue?(e)
      e.kind_of?(self) ? e.lvalue? : (e.kind_of? Variable and e.name)
    end
    def lvalue?
      case @op
      when :*; true if not @lexpr
      when :'[]', :'.', :'->'; true
      when nil	# cast
        CExpression.lvalue?(@rexpr)
      else false
      end
    end

    def self.constant?(e)
      e.kind_of?(self) ? e.constant? : true
    end
    def constant?
      # gcc considers '1, 2' not constant
      if [:',', :funcall, :'=', :'--', :'++', :'+=', :'-=', :'*=', :'/=', :'>>=', :'<<=', :'&=', :'|=', :'^=', :'%=', :'->', :'[]'].include?(@op)
        false
      elsif @op == :'*' and not @lexpr; false
      elsif not @lexpr and not @op and @rexpr.kind_of? Block; false
      else
        out = true
        walk { |e| break out = false if not CExpression.constant?(e) }
        out
      end
    end

    def self.reduce(parser, e)
      e.kind_of?(self) ? e.reduce(parser) : e
    end
    def reduce(parser)
      # parser used for arithmetic overflows (need basic type sizes)
      case @op
      when :'&&'
        case l = CExpression.reduce(parser, @lexpr)
        when 0; 0
        when ::Integer
          case r = CExpression.reduce(parser, @rexpr)
          when 0; 0
          when ::Integer; 1
          else CExpression.new(l, @op, r, @type)
          end
        else CExpression.new(l, @op, @rexpr, @type)
        end
      when :'||'
        case l = CExpression.reduce(parser, @lexpr)
        when 0
          case r = CExpression.reduce(parser, @rexpr)
          when 0; 0
          when ::Integer; 1
          else CExpression.new(l, @op, r, @type)
          end
        when ::Integer; 1
        else CExpression.new(l, @op, @rexpr, @type)
        end
      when :'!'
        case r = CExpression.reduce(parser, @rexpr)
        when 0; 1
        when ::Integer; 0
        else CExpression.new(nil, @op, r, @type)
        end
      when :'!=', :'==', :'<', :'>', :'>=', :'<='
        l = CExpression.reduce(parser, @lexpr)
        r = CExpression.reduce(parser, @rexpr)
        if l.kind_of?(::Integer) and r.kind_of?(::Integer)
          if @op == :'!='; l != r ? 1 : 0
          else l.send(@op, r) ? 1 : 0
          end
        else
          l = CExpression.new(nil, nil, l, BaseType.new(:int)) if l.kind_of? ::Integer
          r = CExpression.new(nil, nil, r, BaseType.new(:int)) if r.kind_of? ::Integer
          CExpression.new(l, @op, r, @type)
        end
      when :'.'
        le = CExpression.reduce(parser, @lexpr)
        if le.kind_of? Variable and le.initializer.kind_of? ::Array
          t = le.type.untypedef
          midx = t.members.index(t.findmember(@rexpr))
          CExpression.reduce(parser, le.initializer[midx] || 0)
        else
          CExpression.new(le, @op, @rexpr, @type)
        end
      when :'?:'
        case c = CExpression.reduce(parser, @lexpr)
        when 0;         CExpression.reduce(parser, @rexpr[0])
        when ::Integer; CExpression.reduce(parser, @rexpr[1])
        else CExpression.new(c, @op, @rexpr, @type)
        end
      when :'+', :'-', :'*', :'/', :'^', :'%', :'&', :'|', :'>>', :'<<', :'~', nil
        t = @type.untypedef
        case t
        when BaseType
        when Pointer; return self if @op
        else
          return @rexpr if not @op and not @lexpr and @rexpr.kind_of? Variable and @rexpr.type == @type
          return self # raise parser, 'not arithmetic type'
        end

        # compute value
        r = CExpression.reduce(parser, @rexpr)
        ret = \
        if not @lexpr
          # unary
          case @op
          when :'+', nil, :'-', :'~'
            return CExpression.new(nil, @op, r, @type) if not r.kind_of? ::Numeric
            case @op
            when :'-'; -r
            when :'~'; ~r
            else r
            end
          else return CExpression.new(nil, @op, r, @type)
          end
        else
          l = CExpression.reduce(parser, @lexpr)
          if not l.kind_of?(::Numeric) or not r.kind_of?(::Numeric)
            l = CExpression.new(nil, nil, l, BaseType.new(:int)) if l.kind_of? ::Integer
            r = CExpression.new(nil, nil, r, BaseType.new(:int)) if r.kind_of? ::Integer
            return CExpression.new(l, @op, r, @type)
          end
          l.send(@op, r)
        end

        # overflow
        tn = (t.pointer? ? :ptr : t.name)
        case tn
        when :char, :short, :int, :long, :ptr, :longlong, :__int8, :__int16, :__int32, :__int64
          max = 1 << (8*parser.typesize[tn])
          ret = ret.to_i & (max-1)
          if not t.pointer? and t.specifier != :unsigned and (ret & (max >> 1)) > 0	# char == unsigned char
            ret - max
          else
            ret
          end
        when :float, :double, :longdouble
          ret.to_f	# TODO
        end
      when :funcall
        l = CExpression.reduce(parser, @lexpr)
        r = @rexpr.map { |rr|
          rr = CExpression.reduce(parser, rr)
          rr = CExpression.new(nil, nil, rr, BaseType.new(:int)) if rr.kind_of? ::Integer
          rr
        }
        CExpression.new(l, @op, r, @type)
      else
        l = CExpression.reduce(parser, @lexpr) if @lexpr
        r = CExpression.reduce(parser, @rexpr) if @rexpr
        l = CExpression.new(nil, nil, l, BaseType.new(:int)) if l.kind_of? ::Integer
        r = CExpression.new(nil, nil, r, BaseType.new(:int)) if r.kind_of? ::Integer
        CExpression.new(l, @op, r, @type)
      end
    end

    def ==(o)
      o.object_id == self.object_id or
      (self.class == o.class and op == o.op and lexpr == o.lexpr and rexpr == o.rexpr)
    end

    def ===(o)
      (self.class == o.class and op == o.op and lexpr === o.lexpr and rexpr === o.rexpr) or
      (o.class == Variable and not @op and @rexpr == o)
    end

    NegateOp = { :== => :'!=', :'!=' => :==, :> => :<=, :>= => :<, :< => :>=, :<= => :> }
    # returns a CExpr negating this one (eg 'x' => '!x', 'a > b' => 'a <= b'...)
    def self.negate(e)
      e.kind_of?(self) ? e.negate : CExpression[:'!', e]
    end
    def negate
      if @op == :'!'
        CExpression[@rexpr]
      elsif nop = NegateOp[@op]
        if nop == :== and @rexpr.kind_of? CExpression and not @rexpr.op and @rexpr.rexpr == 0 and
            @lexpr.kind_of? CExpression and [:==, :'!=', :>, :<, :>=, :<=, :'!'].include? @lexpr.op
          # (a > b) != 0  =>  (a > b)
          CExpression[@lexpr]
        else
          CExpression.new(@lexpr, nop, @rexpr, @type)
        end
      elsif nop = { :'||' => :'&&', :'&&' => :'||' }[@op]
        CExpression.new(CExpression.negate(@lexpr), nop, CExpression.negate(@rexpr), @type)
      else
        CExpression[:'!', self]
      end
    end

    def walk
      case @op
      when :funcall, :'?:'
        yield @lexpr
        @rexpr.each { |arg| yield arg }
      when :'->', :'.'
        yield @lexpr
      else
        yield @lexpr if @lexpr
        yield @rexpr if @rexpr
      end
    end

    def complexity
      cx = 1
      walk { |e| cx += e.complexity if e.kind_of?(CExpression) }
      cx
    end

    RIGHTASSOC = [:'=', :'+=', :'-=', :'*=', :'/=', :'%=', :'&=',
      :'|=', :'^=', :'<<=', :'>>=', :'?:'
    ].inject({}) { |h, op| h.update op => true }

    # key = operator, value = hash regrouping operators of lower precedence
    # funcall/array index/member dereference/sizeof are handled in parse_value
    OP_PRIO = [[:','], [:'?:'], [:'=', :'+=', :'-=', :'*=', :'/=',
      :'%=', :'&=', :'|=', :'^=', :'<<=', :'>>='], [:'||'],
      [:'&&'], [:|], [:^], [:&], [:'==', :'!='],
      [:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-],
      [:*, :/, :%], ].inject({}) { |h, oplist|
        lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
        oplist.each { |op| lessprio.update op => true } if RIGHTASSOC[oplist.first]
        oplist.each { |op| h[op] = lessprio }
        h }

  class << self
    # reads a binary operator from the parser, returns the corresponding symbol or nil
    def readop(parser)
      if not op = parser.skipspaces or op.type != :punct
        parser.unreadtok op
        return
      end

      case op.raw
      when '>', '<', '|', '&' # << >> || &&
        if ntok = parser.readtok and ntok.type == :punct and ntok.raw == op.raw
          op.raw << ntok.raw
        else
          parser.unreadtok ntok
        end
      when '!' # != (mandatory)
        if not ntok = parser.readtok or ntok.type != :punct and ntok.raw != '='
          parser.unreadtok op
          return
        end
        op.raw << ntok.raw
      when '+', '-', '*', '/', '%', '^', '=', ',', '?', ':', '>>', '<<', '||', '&&',
           '+=','-=','*=','/=','%=','^=','==','&=','|=','!=' # ok
      else # bad
        parser.unreadtok op
        return
      end

      # may be followed by '='
      case op.raw
      when '+', '-', '*', '/', '%', '^', '&', '|', '>>', '<<', '<', '>', '='
        if ntok = parser.readtok and ntok.type == :punct and ntok.raw == '='
          op.raw << ntok.raw
        else
          parser.unreadtok ntok
        end
      end

      op.value = op.raw.to_sym
      op
    end

    # parse sizeof offsetof float immediate etc into tok.value
    def parse_intfloat(parser, scope, tok)
      if tok.type == :string and not tok.value
        case tok.raw
        when 'sizeof'
          if ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '('
            # check type
            if v = Variable.parse_type(parser, scope)
              v.parse_declarator(parser, scope)
              raise tok if v.name != false
              raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            else
              raise tok, 'expr expected' if not v = parse(parser, scope)
              raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            end
          else
            parser.unreadtok ntok
            raise tok, 'expr expected' if not v = parse_value(parser, scope)
          end
          tok.value = parser.sizeof(v)
          return
        when '__builtin_offsetof'
          raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != '('
          raise tok if not ntok = parser.skipspaces or ntok.type != :string or ntok.raw != 'struct'
          raise tok if not ntok = parser.skipspaces or ntok.type != :string
          raise tok, 'unknown structure' if not struct = scope.struct_ancestors[ntok.raw] or not struct.kind_of? Union or not struct.members
          raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ','
          raise tok if not ntok = parser.skipspaces or ntok.type != :string
          tok.value = struct.offsetof(parser, ntok.raw)
          raise tok if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
          return
        end
      end

      Expression.parse_num_value(parser, tok)
    end

    # returns the next value from parser (parenthesised expression, immediate, variable, unary operators)
    def parse_value(parser, scope)
      return if not tok = parser.skipspaces
      case tok.type
      when :string
        parse_intfloat(parser, scope, tok)
        val = tok.value || tok.raw
        if val.kind_of? ::String
          raise tok, 'undefined variable' if not val = scope.symbol_ancestors[val]
        end
        case val
        when Type
          raise tok, 'invalid variable'
        when Variable
          val = parse_value_postfix(parser, scope, val)
        when ::Float
          # parse suffix
          type = :double
          if (?0..?9).include?(tok.raw[0])
            case tok.raw.downcase[-1]
            when ?l; type = :longdouble
            when ?f; type = :float
            end
          end
          val = CExpression[val, BaseType.new(type)]

        when ::Integer
          # parse suffix
          # XXX 010h ?
          type = :int
          specifier = []
          if (?0..?9).include?(tok.raw[0])
            suffix = tok.raw.downcase[-3, 3] || tok.raw.downcase[-2, 2] || tok.raw.downcase[-1, 1]	# short string
            specifier << :unsigned if suffix.include?('u') # XXX or tok.raw.downcase[1] == ?x
            type = :longlong if suffix.count('l') == 2
            type = :long if suffix.count('l') == 1
          end
          val = CExpression[val, BaseType.new(type, *specifier)]
          val = parse_value_postfix(parser, scope, val)
        else raise parser, "internal error #{val.inspect}"
        end

      when :quoted
        if tok.raw[0] == ?'
          raise tok, 'invalid character constant' if not [1, 2, 4, 8].include? tok.value.length	# TODO 0fill
          val = CExpression[Expression.decode_imm(tok.value, tok.value.length, :big), BaseType.new(:int)]
          val = parse_value_postfix(parser, scope, val)
        else
          val = CExpression[tok.value, Pointer.new(BaseType.new(tok.raw[0, 2] == 'L"' ? :short : :char))]
          val = parse_value_postfix(parser, scope, val)
        end

      when :punct
        case tok.raw
        when '('
          ntok = nil
          # check type casting
          if v = Variable.parse_type(parser, scope)
            v.parse_declarator(parser, scope)
            (v.type.attributes ||= []).concat v.attributes if v.attributes
            raise tok, 'bad cast' if v.name != false
            raise ntok || tok, 'no ")" found' if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            raise ntok, 'expr expected' if not val = parse_value(parser, scope)	# parses postfix too
            #raise ntok, 'unable to cast a struct' if val.type.untypedef.kind_of? Union
            val = CExpression[[val], v.type]
          # check compound statement expression
          elsif ntok = parser.skipspaces and ntok.type == :punct and ntok.raw == '{'
            parser.unreadtok ntok
            blk = parser.parse_statement(scope, [:expression]) # XXX nesting ?
            raise ntok || tok, 'no ")" found' if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'
            type = blk.statements.last.kind_of?(CExpression) ? blk.statements.last.type : BaseType.new(:void)
            val = CExpression[blk, type]
          else
            parser.unreadtok ntok
            if not val = parse(parser, scope)
              parser.unreadtok tok
              return
            end
            raise ntok || tok, 'no ")" found' if not ntok = parser.readtok or ntok.type != :punct or ntok.raw != ')'
            val = parse_value_postfix(parser, scope, val)
          end
        when '.'	# float
          parse_intfloat(parser, scope, tok)
          if not tok.value
            parser.unreadtok tok
            return
          end
          val = tok.value || tok.raw
          type = :double
          case tok.raw.downcase[-1]
          when ?l; type = :longdouble
          when ?f; type = :float
          end
          val = CExpression.new[val, BaseType.new(type)]

        when '+', '-', '&', '!', '~', '*', '--', '++', '&&'
          # unary prefix
          # may have been read ahead

          raise parser if not ntok = parser.readtok
          # check for -- ++ &&
          if ntok.type == :punct and ntok.raw == tok.raw and %w[+ - &].include?(tok.raw)
            tok.raw << ntok.raw
          else
            parser.unreadtok ntok
          end

          case tok.raw
          when '&'
            val = parse_value(parser, scope)
            if val.kind_of? CExpression and val.op == :& and not val.lexpr and
              (val.rexpr.kind_of? Variable or val.rexpr.kind_of? CExpression) and val.rexpr.type.kind_of? Function
              # &&function == &function
            elsif (val.kind_of? CExpression or val.kind_of? Variable) and val.type.kind_of? Array
              # &ary = ary
            else
              raise parser, "invalid lvalue #{val}" if not CExpression.lvalue?(val) and not parser.allow_bad_c
              raise val.backtrace, 'cannot take addr of register' if val.kind_of? Variable and val.storage == :register and not parser.allow_bad_c
              val = CExpression.new(nil, tok.raw.to_sym, val, Pointer.new(val.type))
            end
          when '++', '--'
            val = parse_value(parser, scope)
            raise parser, "invalid lvalue #{val}" if not CExpression.lvalue?(val) and not parser.allow_bad_c
            val = CExpression.new(nil, tok.raw.to_sym, val, val.type)
          when '&&'
            raise tok, 'label name expected' if not val = parser.skipspaces or val.type != :string
            val = CExpression.new(nil, nil, Label.new(val.raw, nil), Pointer.new(BaseType.new(:void)))
          when '*'
            raise tok, 'expr expected' if not val = parse_value(parser, scope)
            raise tok, 'not a pointer' if not val.type.pointer? and not parser.allow_bad_c
            newtype = val.type.pointer? ? val.type.pointed : BaseType.new(:int)
            if not newtype.untypedef.kind_of? Function	# *fptr == fptr
              val = CExpression.new(nil, tok.raw.to_sym, val, newtype)
            end
          when '~', '!', '+', '-'
            raise tok, 'expr expected' if not val = parse_value(parser, scope)
            raise tok, 'type not arithmetic' if not val.type.arithmetic? and not parser.allow_bad_c
            val = CExpression.new(nil, tok.raw.to_sym, val, val.type)
            val.type = BaseType.new(:int) if tok.raw == '!'
          else raise tok, 'internal error'
          end
        else
          parser.unreadtok tok
          return
        end
      else
        parser.unreadtok tok
        return
      end

      if val.kind_of? Variable and val.type.kind_of? Function
        # void (*bla)() = printf;  =>  ...= &printf;
        val = CExpression[:&, val]
      end

      val
    end

    # parse postfix forms (postincrement, array index, struct member dereference)
    def parse_value_postfix(parser, scope, val)
      tok = parser.skipspaces
      nval = \
      if tok and tok.type == :punct
        case tok.raw
        when '+', '++', '-', '--', '->'
          ntok = parser.readtok
          if (tok.raw == '+' or tok.raw == '-') and ntok and ntok.type == :punct and
              (ntok.raw == tok.raw or (tok.raw == '-' and ntok.raw == '>'))
            tok.raw << ntok.raw
          else
            parser.unreadtok ntok
          end
          case tok.raw
          when '+', '-'
            nil
          when '++', '--'
            raise parser, "#{val}: invalid lvalue" if not CExpression.lvalue?(val)
            CExpression.new(val, tok.raw.to_sym, nil, val.type)
          when '->'
            # XXX allow_bad_c..
            raise tok, "#{val}: not a pointer" if not val.type.pointer?
            type = val.type.pointed.untypedef
            raise tok, "#{val}: bad pointer" if not type.kind_of? Union
            raise tok, "#{val}: incomplete type" if not type.members
            raise tok, "#{val}: invalid member" if not tok = parser.skipspaces or tok.type != :string or not m = type.findmember(tok.raw)
            CExpression.new(val, :'->', tok.raw, m.type)
          end
        when '.'
          type = val.type.untypedef
          if not ntok = parser.skipspaces or ntok.type != :string or not type.kind_of? Union
            parser.unreadtok ntok
            nil
          else
            raise ntok, "#{val}: incomplete type" if not type.members
            raise ntok, "#{val}: invalid member" if not m = type.findmember(ntok.raw)
            CExpression.new(val, :'.', ntok.raw, m.type)
          end
        when '['
          raise tok, "#{val}: index expected" if not idx = parse(parser, scope)
          val, idx = idx, val        if not val.type.pointer?		# fake support of "4[tab]"
          raise tok, "#{val}: not a pointer" if not val.type.pointer?
          raise tok, "#{val}: invalid index"  if not idx.type.integral?
          raise tok, "#{val}: get perpendicular ! (elsewhere)" if idx.kind_of?(CExpression) and idx.op == :','
          raise tok || parser, "']' expected" if not tok = parser.skipspaces or tok.type != :punct or tok.raw != ']'
          type = val.type.untypedef.type
          # TODO boundscheck (and become king of the universe)
          CExpression.new(val, :'[]', idx, type)
        when '('
          type = val.type.untypedef
          type = type.type.untypedef if type.kind_of? Pointer
          raise tok, "#{val}: not a function" if not type.kind_of? Function

          args = []
          loop do
            a = parse(parser, scope, false)
            break if not a
            args << a
            if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ','
              parser.unreadtok ntok
              break
            end
          end
          raise ntok || parser, "#{val}: ')' expected" if not ntok = parser.skipspaces or ntok.type != :punct or ntok.raw != ')'

          type.args ||= []
          raise tok, "#{val}: bad argument count: #{args.length} for #{type.args.length}" if (type.varargs ? (args.length < type.args.length) : (args.length != type.args.length))
          type.args.zip(args) { |ta, a|
            p, i = ta.type.pointer?, ta.type.integral?
            r = a.reduce(parser) if p or i
            if (not p and not i) or (i and not r.kind_of? ::Integer) or (p and r != 0)
              tok = tok.dup ; tok.raw = a.to_s
              parser.check_compatible_type(tok, a.type, ta.type)
            end
          }
          CExpression.new(val, :funcall, args, type.type)
        end
      end

      if nval
        parse_value_postfix(parser, scope, nval)
      else
        parser.unreadtok tok
        val
      end
    end

    def parse_popstack(parser, stack, opstack)
      r = stack.pop
      l = stack.pop
      case op = opstack.pop
      when :'?:'
        stack << CExpression.new(stack.pop, op, [l, r], l.type)
      when :','
        stack << CExpression.new(l, op, r, r.type)
      when :'='
        unless r.kind_of?(CExpression) and not r.lexpr and r.type.kind_of?(BaseType) and
            ((not r.op and r.rexpr.kind_of?(Integer)) or
             (r.op == :- and r.rexpr.kind_of?(CExpression) and not r.rexpr.op and not r.rexpr.lexpr and r.rexpr.rexpr.kind_of?(Integer))) and
             l.kind_of?(Typed) and (l.type.untypedef.kind_of?(BaseType) or (l.type.untypedef.kind_of?(Pointer) and r.rexpr == 0))
          # avoid useless warnings on unsigned foo = -1  /  void *foo = 0
          parser.check_compatible_type(parser, r.type, l.type)
        end
        if l.kind_of?(Typed) and (lt = l.type.untypedef).kind_of?(BaseType) and r.kind_of?(Typed) and (rt = r.type.untypedef).kind_of?(BaseType) and lt.specifier != :unsigned and rt.specifier == :unsigned and parser.typesize[lt.name] > parser.typesize[rt.name]
          # (int32)i = (uchar)255 => 255, not -1
          r = CExpression.new(nil, nil, r, BaseType.new(lt.name, :unsigned))
        end
        stack << CExpression.new(l, op, r, l.type)
      when :'&&', :'||'
        stack << CExpression.new(l, op, r, BaseType.new(:int))
      else
        # XXX struct == struct ?
        raise parser, "invalid type #{l.type} #{l} for #{op.inspect}" if not l.type.arithmetic? and not parser.allow_bad_c
        raise parser, "invalid type #{r.type} #{r} for #{op.inspect}" if not r.type.arithmetic? and not parser.allow_bad_c

        if l.type.pointer? and r.type.pointer?
          type = \
          case op
          when :'-'; BaseType.new(:long)	# addr_t or sumthin ?
          when :'-='; l.type
          when :'>', :'>=', :'<', :'<=', :'==', :'!='; BaseType.new(:long)
          else raise parser, "cannot do #{op.inspect} on pointers" unless parser.allow_bad_c ; l.type
          end
        elsif l.type.pointer? or r.type.pointer?
          puts parser.exception("should not #{op.inspect} a pointer").message if $VERBOSE and not [:'+', :'-', :'=', :'+=', :'-=', :==, :'!='].include? op
          type = l.type.pointer? ? l.type : r.type
        elsif RIGHTASSOC[op] and op != :'?:'	# += etc
          type = l.type
        else
          # yay integer promotion
          lt = l.type.untypedef
          rt = r.type.untypedef
          if    (t = lt).name == :longdouble or (t = rt).name == :longdouble or
                (t = lt).name == :double or (t = rt).name == :double or
                (t = lt).name == :float or (t = rt).name == :float
          # long double > double > float ...
            type = t
          elsif true
            # custom integer rules based on type sizes
            lts = parser.typesize[lt.name]
            rts = parser.typesize[rt.name]
            its = parser.typesize[:int]
            if not lts or not rts
              type = BaseType.new(:int)
            elsif lts >  rts and lts >= its
              type = lt
            elsif rts >  lts and rts >= its
              type = rt
            elsif lts == rts and lts >= its
              type = lt
              type = rt if rt.specifier == :unsigned
            else
              type = BaseType.new(:int)
            end
            # end of custom rules
          elsif ((t = lt).name == :long and t.specifier == :unsigned) or
                ((t = rt).name == :long and t.specifier == :unsigned)
          # ... ulong ...
            type = t
          elsif (lt.name == :long and rt.name == :int and rt.specifier == :unsigned) or
                (rt.name == :long and lt.name == :int and lt.specifier == :unsigned)
          # long+uint => ulong
            type = BaseType.new(:long, :unsigned)
          elsif (t = lt).name == :long or (t = rt).name == :long or
                ((t = lt).name == :int and t.specifier == :unsigned) or
                ((t = rt).name == :int and t.specifier == :unsigned)
          # ... long > uint ...
            type = t
          else
          # int
            type = BaseType.new(:int)
          end
        end

        case op
        when :'>', :'>=', :'<', :'<=', :'==', :'!='
          # cast both sides
          l = CExpression[l, type] if l.type != type
          r = CExpression[r, type] if r.type != type
          stack << CExpression.new(l, op, r, BaseType.new(:int))
        else
          # promote result
          stack << CExpression.new(l, op, r, type)
        end
      end
    end

    def parse(parser, scope, allow_coma = true)
      opstack = []
      stack = []

      return if not e = parse_value(parser, scope)

      stack << e

      while op = readop(parser)
        case op.value
        when :'?'
          # a, b ? c, d : e, f  ==  a, (b ? (c, d) : e), f
          until opstack.empty? or OP_PRIO[opstack.last][:'?:']
            parse_popstack(parser, stack, opstack)
          end
          stack << parse(parser, scope)
          raise op || parser, '":" expected' if not op = readop(parser) or op.value != :':'
          op = op.dup
          op.value = :'?:'
        when :':'
          parser.unreadtok op
          break
        else
          if not allow_coma and op.value == :','
            parser.unreadtok op
            break
          end
          until opstack.empty? or OP_PRIO[op.value][opstack.last]
            parse_popstack(parser, stack, opstack)
          end
        end

        raise op, 'need rhs' if not e = parse_value(parser, scope)
        stack << e
        opstack << op.value
      end

      until opstack.empty?
        parse_popstack(parser, stack, opstack)
      end

      CExpression[stack.first]
    end
  end
  end



  #
  # AllocCStruct: ruby interpreter memory-mapped structure
  #

  # this maps a C structure from a C parser to a ruby String
  # struct members are accessed through obj['fldname']
  # obj.fldname is an alias
  class AllocCStruct
    # str is a reference to the underlying ruby String
    # stroff is the offset from the start of this string (non-nul for nested structs)
    # cp is a reference to the C::Parser
    # struct to the C::Union/Struct/Array
    # sizeof is the byte size of the C struct
    attr_accessor :str, :stroff, :cp, :struct
    attr_writer :sizeof
    def initialize(cp, struct, str=nil, stroff=0)
      @cp, @struct = cp, struct
      @str = str || [0].pack('C')*sizeof
      @stroff = stroff
    end

    def sizeof
      @sizeof ||= @cp.sizeof(@struct)
    end

    def [](*a)
      if @struct.kind_of? C::Array and a.length == 1 and @struct.length and a[0].kind_of? Integer
        i = a[0]
        raise "#{i} out of bounds 0...#{@struct.length}" if  i < 0 or i >= @struct.length
        off = @stroff + i*@cp.sizeof(@struct.type)
        return @cp.decode_c_value(@str, @struct.type, off)
      end

      return @str[@stroff..-1][*a] if a.length != 1
      a = a.first
      return @str[@stroff..-1][a] if not a.kind_of? Symbol and not a.kind_of? String and not a.kind_of? C::Variable
      f = a
      raise "#{a.inspect} not a member" if not f.kind_of? C::Variable and not f = @struct.findmember(a.to_s, true)
      a = f.name || f
      off = @stroff + @struct.offsetof(@cp, a)
      if bf = @struct.bitoffsetof(@cp, a)
        ft = C::BaseType.new((bf[0] + bf[1] > 32) ? :__int64 : :__int32)
        v = @cp.decode_c_value(@str, ft, off)
        (v >> bf[0]) & ((1 << bf[1])-1)
      else
        @cp.decode_c_value(@str, f, off)
      end
    end

    def []=(*a)
      if @struct.kind_of? C::Array and a.length == 2 and @struct.length and a[0].kind_of? Integer
        i = a[0]
        raise "#{i} out of bounds 0...#{@struct.length}" if  i < 0 or i >= @struct.length
        off = @stroff + i*@cp.sizeof(@struct.type)
        val = @cp.encode_c_value(@struct.type, a[1])
        @str[off, val.length] = val
        return
      end

      if not a.first.kind_of? Symbol and not a.first.kind_of? String and not a.first.kind_of? C::Variable
        # patch @str[@stroff..-1] like a string
        # so we must find the intended start offset, and add @stroff to it
        if @stroff != 0
          case a.first
          when Range
            if a.first.begin >= 0
              a[0] = ::Range.new(a[0].begin+@stroff, a[0].end+@stroff, a[0].exclude_end?)
            else raise 'no can do, use positive index'
            end
          when Integer
            if a.first >= 0
              a[0] += @stroff
            else raise 'no can do, use positive index'
            end
          else raise 'no can do'
          end
        end

        return @str.send(:'[]=', *a)	# XXX *should* work...
      end

      a, val = a
      f = a
      raise "#{a.inspect} not a struct member" if not f.kind_of? C::Variable and not f = @struct.findmember(a.to_s, true)
      a = f.name || f
      val = sizeof if val == :size
      off = @stroff + @struct.offsetof(@cp, a)

      if bf = @struct.bitoffsetof(@cp, a)
        raise "only Integers supported in bitfield #{a}, got #{val.inspect}" if not val.kind_of?(::Integer)
        # struct { int i:8; };  =>  size 8 or 32 ?
        ft = C::BaseType.new((bf[0] + bf[1] > 32) ? :__int64 : :__int32)
        mask = ((1 << bf[1]) - 1) << bf[0]
        preval = @cp.decode_c_value(@str, ft, off)
        val = (preval & ~mask) | ((val << bf[0]) & mask)
        f = ft
      end

      val = @cp.encode_c_value(f, val)
      @str[off, val.length] = val
    end

    # virtual accessors to members
    # struct.foo is aliased to struct['foo'],
    # struct.foo = 42 aliased to struct['foo'] = 42
    def method_missing(on, *a)
      n = on.to_s
      if n[-1] == ?=
        send :[]=, n[0...-1], *a
      else
        super(on, *a) if not @struct.kind_of?(C::Union) or not @struct.findmember(n, true)
        send :[], n, *a
      end
    end

    def to_s(off=nil, maxdepth=500)
      return '{ /* ... */ }' if maxdepth <= 0
      str = ['']
      if @struct.kind_of?(C::Array)
        str.last << "#{@struct.type} x[#{@struct.length}] = " if not off
        mlist = (0...@struct.length)
        fldoff = mlist.inject({}) { |h, i| h.update i => i*@cp.sizeof(@struct.type) }
      elsif @struct.kind_of?(C::Struct)
        str.last << "struct #{@struct.name || '_'} x = " if not off
        @struct.update_member_cache(@cp) if not @struct.fldlist
        fldoff = @struct.fldoffset
        mlist = @struct.members.map { |m| m.name || m }
      else
        str.last << "union #{@struct.name || '_'} x = " if not off
        mlist = @struct.members.map { |m| m.name || m }
      end
      str.last << '{'
      mlist.each { |k|
        if k.kind_of? Variable	# anonymous member
          curoff = off.to_i + @struct.offsetof(@cp, k)
          val = self[k]
          k = '?'
        else
          curoff = off.to_i + (fldoff ? fldoff[k].to_i : 0)
          val = self[k]
        end
        if val.kind_of?(::Integer)
          if val >= 0x100
            val = '0x%X,   // +%x' % [val, curoff]
          elsif val <= -0x100
            val = '-0x%X,   // +%x' % [-val, curoff]
          else
            val = '%d,   // +%x' % [val, curoff]
          end
        elsif val.kind_of? AllocCStruct
          val = val.to_s(curoff, maxdepth-1)
        elsif not val
          val = 'NULL,   // +%x' % curoff # pointer with NULL value
        else
          val = val.to_s.sub(/$/, ',   // +%x' % curoff)
        end
        val = val.gsub("\n", "\n\t")
        str << "\t#{k.kind_of?(::Integer) ? "[#{k}]" : ".#{k}"} = #{val}"
      }
      str << '}'
      str.last << (off ? ',' : ';')
      str.join("\n")
    end

    def to_array
      raise NoMethodError, "Not an Array" if not @struct.kind_of?(C::Array)
      ary = []
      @struct.length.times { |i| ary << self[i] }
      ary
    end

    def to_strz
      raise NoMethodError, "Not an Array" if not @struct.kind_of?(C::Array)
      a = to_array
      a[a.index(0)..-1] = [] if a.index(0)
      a.pack('C*')
    end
  end

  class Parser
    # find a Struct/Union object from a struct name/typedef name
    # raises if it cant find it
    def find_c_struct(structname)
      structname = structname.to_s if structname.kind_of?(::Symbol)
      if structname.kind_of?(::String) and not struct = @toplevel.struct[structname]
        struct = @toplevel.symbol[structname]
        raise "unknown struct #{structname.inspect}" if not struct
        struct = struct.type.untypedef
        struct = struct.pointed while struct.pointer?
        raise "unknown struct #{structname.inspect}" if not struct.kind_of? C::Union
      end
      struct = structname if structname.kind_of? C::Union
      raise "unknown struct #{structname.inspect}" if not struct.kind_of? C::Union
      struct
    end

    # find a C::Type (struct/union/typedef/basetype) from a string
    def find_c_type(typename)
      typename = typename.to_s if typename.kind_of? ::Symbol
      if typename.kind_of?(::String) and not type = @toplevel.struct[typename]
        if type = @toplevel.symbol[typename]
          type = type.type.untypedef
        else
          begin
            lexer.feed(typename)
            b = C::Block.new(@toplevel)
            var = Variable.parse_type(self, b)
            var.parse_declarator(self, b)
            type = var.type
          rescue
          end
        end
      end
      type = typename if typename.kind_of?(C::Type)
      raise "unknown type #{typename.inspect}" if not type.kind_of? C::Type
      type
    end

    # allocate a new AllocCStruct from the struct/struct typedef name of the current toplevel
    # optionally populate the fields using the 'values' hash
    def alloc_c_struct(structname, values=nil)
      struct = find_c_struct(structname)
      st = AllocCStruct.new(self, struct)
      values.each { |k, v| st[k] = v } if values
      st
    end

    # parse a given String as an AllocCStruct
    # offset is an optionnal offset from the string start
    # modification to the structure will modify the underlying string
    def decode_c_struct(structname, str, offset=0)
      struct = find_c_struct(structname)
      AllocCStruct.new(self, struct, str, offset)
    end

    # allocate an array of types
    # init is either the length of the array, or an array of initial values
    def alloc_c_ary(typename, init=1)
      type = find_c_type(typename)
      len = init.kind_of?(Integer) ? init : init.length
      struct = C::Array.new(type, len)
      st = AllocCStruct.new(self, struct)
      if init.kind_of?(::Array)
        init.each_with_index { |v, i|
          st[i] = v
        }
      end
      st
    end

    # "cast" a string to C::Array
    def decode_c_ary(typename, len, str, offset=0)
      type = find_c_type(typename)
      struct = C::Array.new(type, len)
      AllocCStruct.new(self, struct, str, offset)
    end

    # convert (pack) a ruby value into a C buffer
    # packs integers, converts Strings to their C pointer (using DynLdr)
    def encode_c_value(type, val)
      type = type.type if type.kind_of? Variable

      case val
      when nil; val = 0
      when ::Integer
      when ::String
        val = DynLdr.str_ptr(val)
      when ::Hash
        type = type.pointed while type.pointer?
        raise "need a struct ptr for #{type} #{val.inspect}" if not type.kind_of? Union
        buf = alloc_c_struct(type, val)
        val.instance_variable_set('@rb2c', buf) # GC trick
        val = buf
      when ::Proc
        val = DynLdr.convert_rb2c(type, val)	# allocate a DynLdr callback
      when AllocCStruct
        val = DynLdr.str_ptr(val.str) + val.stroff
      #when ::Float		# TODO
      else raise "TODO #{val.inspect}"
      end

      val = Expression.encode_immediate(val, sizeof(type), @endianness) if val.kind_of?(::Integer)

      val
    end

    def decode_c_value(str, type, off=0)
      type = type.type if type.kind_of? Variable
      type = type.untypedef
      if type.kind_of? C::Union or type.kind_of? C::Array
        return AllocCStruct.new(self, type, str, off)
      end
      val = Expression.decode_immediate(str, sizeof(type), @endianness, off)
      val = Expression.make_signed(val, sizeof(type)*8) if type.integral? and type.signed?
      val = nil if val == 0 and type.pointer?
      val
    end
  end


  #
  # Dumper : objects => C source
  #

  class Parser
    # returns a big string containing all definitions from headers used in the source (including macros)
    def factorize(*a)
      factorize_init
      parse(*a)
      raise @lexer.readtok || self, 'eof expected' if not @lexer.eos?
      factorize_final
    end

    def factorize_init
      @lexer.traced_macros = []
    end

    def factorize_final
      # now find all types/defs not coming from the standard headers
      # all
      all = @toplevel.struct.values + @toplevel.symbol.values
      all -= all.grep(::Integer)	# Enum values

      # list of definitions of user-defined objects
      userdefined = all.find_all { |t|
        t.backtrace.backtrace.grep(::String).grep(/^</).empty?
      }

      @toplevel.statements.clear	# don't want all Declarations

      # a macro is fine too
      @lexer.dump_macros(@lexer.traced_macros, false) + "\n\n" +
      dump_definitions(userdefined, userdefined)
    end

    # returns a big string representing the definitions of all terms appearing in +list+, excluding +exclude+
    # includes dependencies
    def dump_definitions(list, exclude=[])
      # recurse all dependencies
      todo_rndr = {}
      todo_deps = {}
      list.each { |t|
        todo_rndr[t], todo_deps[t] = t.dump_def(@toplevel)
      }
      # c.toplevel.anonymous_enums.to_a.each { |t| todo_rndr[t], todo_deps[t] = t.dump_def(c.toplevel) }
      while !(ar = (todo_deps.values.flatten - todo_deps.keys)).empty?
        ar.each { |t|
          todo_rndr[t], todo_deps[t] = t.dump_def(@toplevel)
        }
      end
      exclude.each { |t| todo_deps.delete t ; todo_rndr.delete t }
      todo_deps.each_key { |t| todo_deps[t] -= exclude }

      all = @toplevel.struct.values + @toplevel.symbol.values
      all -= all.grep(::Integer)	# Enum values

      @toplevel.dump_reorder(all, todo_rndr, todo_deps)[0].join("\n")
    end

    # returns a string containing the C definition(s) of toplevel functions, with their dependencies
    def dump_definition(*funcnames)
      oldst = @toplevel.statements
      @toplevel.statements = []
      dump_definitions(funcnames.map { |f| @toplevel.symbol[f] })
    ensure
      @toplevel.statements = oldst
    end

    def to_s
      @toplevel.dump(nil)[0].join("\n")
    end
  end

  class Statement
    def self.dump(e, scope, r=[''], dep=[])
      case e
      when nil; r.last << ';'
      when Block
        r.last << ' ' if not r.last.empty?
        r.last << '{'
        tr, dep = e.dump(scope, [''], dep)
        tr.pop if tr.last.empty?
        r.concat tr.map { |s| Case.dump_indent(s) }
        (r.last[-1] == ?{ ? r.last : r) << '}'
      else
        tr, dep = e.dump(scope, [''], dep)
        r.concat tr.map { |s| Case.dump_indent(s) }
      end
      [r, dep]
    end

    def to_s
      dump(Block.new(nil))[0].join(' ')
    end
  end

  class Block
    def to_s() dump(nil)[0].join("\n") end

    # return array of c source lines and array of dependencies (objects)
    def dump(scp, r=[''], dep=[])
      mydefs = @symbol.values.grep(TypeDef) + @struct.values + anonymous_enums.to_a
      todo_rndr = {}
      todo_deps = {}
      mydefs.each { |t| # filter out Enum values
        todo_rndr[t], todo_deps[t] = t.dump_def(self)
      }
      r, dep = dump_reorder(mydefs, todo_rndr, todo_deps, r, dep)
      dep -= @symbol.values + @struct.values
      [r, dep]
    end

    def dump_reorder(mydefs, todo_rndr, todo_deps, r=[''], dep=[])
      val = todo_deps.values.flatten.uniq
      dep |= val
      dep -= mydefs | todo_deps.keys
      todo_deps.each { |k, v| v.delete k }
      ext = val - mydefs
      if ext.length > todo_deps.length
        todo_deps.each_key { |k| todo_deps[k] = todo_deps[k] & mydefs }
      else
        ext.each { |k| todo_deps.each_value { |v| v.delete k } }
      end

      # predeclare structs involved in cyclic dependencies
      dep_cycle = lambda { |ary|
        # sexyness inside (c)
        deps = todo_deps[ary.last]
        if deps.include? ary.first; ary
        elsif (deps-ary).find { |d| deps = dep_cycle[ary + [d]] }; deps
        end
      }
      todo_rndr.keys.grep(Union).find_all { |t| t.name }.sort_by { |t| t.name }.each { |t|
        oldc = nil
        while c = dep_cycle[[t]]
          break if oldc == c
          r << "#{t.kind_of?(Struct) ? 'struct' : 'union'} #{t.name};" if not oldc
          oldc = c
          c.each { |s|
            # XXX struct z { struct a* }; struct a { void (*foo)(struct z); };
            todo_deps[s].delete t unless s.kind_of? Union and
              s.members.find { |sm| sm.type.untypedef == t }
          }
        end
      }

      loop do
        break if todo_rndr.empty?
        todo_now = todo_deps.keys.find_all { |k| todo_deps[k].empty? }
        if todo_now.empty?
          r << '// dependency problem, this may not compile'
          todo_now = todo_deps.keys
        end
        todo_now.sort_by { |k| k.name || '0' }.each { |k|
          if k.kind_of? Variable and k.type.kind_of? Function and k.initializer
            r << ''
            r.concat todo_rndr.delete(k)
          else
            r.pop if r.last == ''
            r.concat todo_rndr.delete(k)
            r.last << ';'
          end
          todo_deps.delete k
        }
        todo_deps.each_key { |k| todo_deps[k] -= todo_now }
        r << '' << '' << ''
      end

      @statements.each { |s|
        r << '' if not r.last.empty?
        if s.kind_of? Block
          r, dep = Statement.dump(s, self, r, dep)
        else
          r, dep = s.dump(self, r, dep)
        end
      }

      [r, dep]
    end
  end
  class Declaration
    def dump(scope, r=[''], dep=[])
      tr, dep = @var.dump_def(scope, [''], dep)
      if @var.kind_of? Variable and @var.type.kind_of? Function and @var.initializer
        r << ''
        r.concat tr
      else
        r.pop if r.last == ''
        r.concat tr
        r.last << ';'
      end
      [r, dep]
    end

    def to_s
      dump(Block.new(nil))[0].join(' ')
    end
  end
  module Attributes
    def dump_attributes
      if attributes
        (attributes - DECLSPECS).map { |a| " __attribute__((#{a}))" }.join
      else ''
      end
    end
    def dump_attributes_pre
      if attributes
        (attributes & DECLSPECS).map { |a| "__#{a} " }.join
      else ''
      end
    end
  end
  class Variable
    def dump(scope, r=[''], dep=[])
      if name
        dep |= [scope.symbol_ancestors[@name]]
        r.last << @name
      end
      [r, dep]
    end
    def dump_def(scope, r=[''], dep=[], skiptype=false)
      # int a=1, b=2;
      r.last << dump_attributes_pre
      if not skiptype
        r.last << @storage.to_s << ' ' if storage
        r, dep = @type.base.dump(scope, r, dep)
        r.last << ' ' if name
      end
      r, dep = @type.dump_declarator([(name ? @name.dup : '') << dump_attributes], scope, r, dep)

      if initializer
        r.last << ' = ' if not @type.kind_of?(Function)
        r, dep = @type.dump_initializer(@initializer, scope, r, dep)
      end
      [r, dep]
    end

    def to_s
      dump(Block.new(nil))[0].join(' ')
    end
  end
  class Type
    def dump_initializer(init, scope, r=[''], dep=[])
      case init
      when ::Numeric
        r.last << init.to_s
        [r, dep]
      when ::Array
        r.last << init.inspect
        [r, dep]
      else init.dump_inner(scope, r, dep)
      end
    end

    def dump_declarator(decl, scope, r=[''], dep=[])
      r.last << decl.shift
      r.concat decl
      [r, dep]
    end

    def dump_def(*a)
      dump(*a)
    end

    def dump_cast(scope, r=[''], dep=[])
      r.last << '('
      r.last << dump_attributes_pre if not kind_of? TypeDef
      r, dep = base.dump(scope, r, dep)
      r, dep = dump_declarator([kind_of?(TypeDef) ? '' : dump_attributes], scope, r, dep)
      r.last << ')'
      [r, dep]
    end

    def to_s
      dump_cast(Block.new(nil))[0].join(' ')
    end
  end
  class Pointer
    def dump_declarator(decl, scope, r=[''], dep=[])
      d = decl[0]
      decl[0] = '*'
      decl[0] << ' ' << @qualifier.map { |q| q.to_s }.join(' ') << ' ' if qualifier
      decl[0] << d
      if @type.kind_of? Function or @type.kind_of? Array
        decl[0] = '(' << decl[0]
        decl.last << ')'
      end
      @type.dump_declarator(decl, scope, r, dep)
    end
  end
  class Array
    def dump_declarator(decl, scope, r=[''], dep=[])
      decl.last << '()' if decl.last.empty?
      decl.last << '['
      decl, dep = CExpression.dump(@length, scope, decl, dep) if length
      decl.last << ']'
      @type.dump_declarator(decl, scope, r, dep)
    end
    def dump_initializer(init, scope, r=[''], dep=[])
      return super(init, scope, r, dep) if not init.kind_of? ::Array
      r.last << '{ '
      showname = false
      init.each_with_index { |v, i|
        if not v
          showname = true
          next
        end
        r.last << ', ' if r.last[-2, 2] != '{ '
        rt = ['']
        if showname
          showname = false
          rt << "[#{i}] = "
        end
        rt, dep = @type.dump_initializer(v, scope, rt, dep)
        r.last << rt.shift
        r.concat rt.map { |s| "\t" << s }
      }
      r.last << ' }'
      [r, dep]
    end
  end
  class Function
    def dump_declarator(decl, scope, r=[''], dep=[])
      decl.last << '()' if decl.last.empty?
      decl.last << '('
      if args
        @args.each { |arg|
          decl.last << ', ' if decl.last[-1] != ?(
          decl, dep = arg.dump_def(scope, decl, dep)
        }
        if varargs
          decl.last << ', ' if decl.last[-1] != ?(
          decl.last << '...'
        else
          decl.last << 'void' if @args.empty?
        end
      end
      decl.last << ')'
      @type.dump_declarator(decl, scope, r, dep)
    end

    def dump_initializer(init, scope, r=[''], dep=[])
      Statement.dump(init, scope, r << '', dep)
    end
  end
  class BaseType
    def dump(scope, r=[''], dep=[])
      r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
      r.last << @specifier.to_s << ' ' if specifier and @name != :ptr
      r.last << case @name
      when :longlong; 'long long'
      when :longdouble; 'long double'
      when :ptr; specifier == :unsigned ? 'uintptr_t' : 'intptr_t'
      else @name.to_s
      end
      [r, dep]
    end
  end
  class TypeDef
    def dump(scope, r=[''], dep=[])
      r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
      r.last << @name
      dep |= [scope.symbol_ancestors[@name]]
      [r, dep]
    end

    def dump_def(scope, r=[''], dep=[])
      r.last << 'typedef '
      r.last << dump_attributes_pre
      r, dep = @type.base.dump(scope, r, dep)
      r.last << ' '
      @type.dump_declarator([(name ? @name.dup : '') << dump_attributes], scope, r, dep)
    end

    def dump_initializer(init, scope, r=[''], dep=[])
      @type.dump_initializer(init, scope, r, dep)
    end
  end
  class Union
    def dump(scope, r=[''], dep=[])
      if name
        r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
        r.last << self.class.name.downcase[/(?:.*::)?(.*)/, 1] << ' ' << @name
        dep |= [scope.struct_ancestors[@name]]
        [r, dep]
      else
        dump_def(scope, r, dep)
      end
    end

    def dump_def(scope, r=[''], dep=[])
      r << ''
      r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
      r.last << self.class.name.downcase[/(?:.*::)?(.*)/, 1]
      r.last << ' ' << @name if name
      if members
        r.last << ' {'
        @members.each_with_index { |m,i|
          tr, dep = m.dump_def(scope, [''], dep)
          tr.last << ':' << @bits[i].to_s if bits and @bits[i]
          tr.last << ';'
          r.concat tr.map { |s| "\t" << s }
        }
        r << '}'
      end
      r.last << dump_attributes
      [r, dep]
    end

    def dump_initializer(init, scope, r=[''], dep=[])
      return super(init, scope, r, dep) if not init.kind_of? ::Array
      r.last << '{ '
      showname = false
      @members.zip(init) { |m, i|
        if not i
          showname = true
          next
        end
        r.last << ', ' if r.last[-2, 2] != '{ '
        rt = ['']
        if showname
          showname = false
          rt << ".#{m.name} = "
        end
        rt, dep = m.type.dump_initializer(i, scope, rt, dep)
        r.last << rt.shift
        r.concat rt.map { |s| "\t" << s }
      }
      r.last << ' }'
      [r, dep]
    end
  end
  class Struct
    def dump_def(scope, r=[''], dep=[])
      if pack
        r, dep = super(scope, r, dep)
        r.last <<
        if @pack == 1; (has_attribute('packed') or has_attribute_var('pack')) ? '' : " __attribute__((packed))"
        else has_attribute_var('pack') ? '' : " __attribute__((pack(#@pack)))"
        end
        [r, dep]
      else
        super(scope, r, dep)
      end
    end
  end
  class Enum
    def dump(scope, r=[''], dep=[])
      if name
        r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
        r.last << 'enum ' << @name
        dep |= [scope.struct_ancestors[@name]]
        [r, dep]
      else
        dump_def(scope, r, dep)
      end
    end

    def dump_def(scope, r=[''], dep=[])
      r.last << @qualifier.map { |q| q.to_s << ' ' }.join if qualifier
      r.last << 'enum'
      r.last << ' ' << @name if name
      if members
        r.last << ' { '
        val = -1
        @members.sort_by { |m, v| v }.each { |m, v|
          r.last << ', ' if r.last[-2, 2] != '{ '
          r.last << m
          if v != (val += 1)
            val = v
            r.last << ' = ' << val.to_s
          end
        }
        r.last << ' }'
      end
      [r, dep]
    end

    def dump_initializer(init, scope, r=[''], dep=[])
      if members and (
          k = @members.index(init) or
          (init.kind_of? CExpression and not init.op and k = @members.index(init.rexpr))
      )
        r.last << k
        dep |= [scope.struct_ancestors[@name]]
        [r, dep]
      else super(init, scope, r, dep)
      end
    end
  end
  class If
    def dump(scope, r=[''], dep=[])
      r.last << 'if ('
      r, dep = CExpression.dump(@test, scope, r, dep)
      r.last << ')'
      r, dep = Statement.dump(@bthen, scope, r, dep)
      if belse
        @bthen.kind_of?(Block) ? (r.last << ' else') : (r << 'else')
        if @belse.kind_of? If
          # skip indent
          r.last << ' '
          r, dep = @belse.dump(scope, r, dep)
        else
          r, dep = Statement.dump(@belse, scope, r, dep)
        end
      end
      [r, dep]
    end
  end
  class For
    def dump(scope, r=[''], dep=[])
      r.last << 'for ('
      if @init.kind_of? Block
        scope = @init
        skiptype = false
        @init.symbol.each_value { |s|
          r.last << ', ' if skiptype
          r, dep = s.dump_def(scope, r, dep, skiptype)
          skiptype = true
        }
      else
        r, dep = CExpression.dump(@init, scope, r, dep)
      end
      r.last << ' ' if @init
      r.last << ';'
      r.last << ' ' if @test
      r, dep = CExpression.dump(@test, scope, r, dep)
      r.last << ' ' if @test
      r.last << ';'
      r.last << ' ' if @iter
      r, dep = CExpression.dump(@iter, scope, r, dep)
      r.last << ')'
      Statement.dump(@body, scope, r, dep)
    end
  end
  class While
    def dump(scope, r=[''], dep=[])
      r.last << 'while ('
      r, dep = CExpression.dump(@test, scope, r, dep)
      r.last << ')'
      Statement.dump(@body, scope, r, dep)
    end
  end
  class DoWhile
    def dump(scope, r=[''], dep=[])
      r.last << 'do'
      r, dep = Statement.dump(@body, scope, r, dep)
      @body.kind_of?(Block) ? (r.last << ' while (') : (r << 'while (')
      r, dep = CExpression.dump(@test, scope, r, dep)
      r.last << ');'
      [r, dep]
    end
  end
  class Switch
    def dump(scope, r=[''], dep=[])
      r.last << 'switch ('
      r, dep = CExpression.dump(@test, scope, r, dep)
      r.last << ')'
      r.last << ' {' if @body.kind_of? Block
      tr, dep = @body.dump(scope, [''], dep)
      r.concat tr.map { |s| Case.dump_indent(s, true) }
      r << '}' if @body.kind_of? Block
      [r, dep]
    end
  end
  class Continue
    def dump(scope, r=[''], dep=[])
      r.last << 'continue;'
      [r, dep]
    end
  end
  class Break
    def dump(scope, r=[''], dep=[])
      r.last << 'break;'
      [r, dep]
    end
  end
  class Goto
    def dump(scope, r=[''], dep=[])
      r.last << "goto #@target;"
      [r, dep]
    end
  end
  class Return
    def dump(scope, r=[''], dep=[])
      r.last << 'return '
      r, dep = CExpression.dump(@value, scope, r, dep)
      r.last.chop! if r.last[-1] == ?\ 	# the space character
      r.last << ';'
      [r, dep]
    end
  end
  class Case
    def dump(scope, r=[''], dep=[])
      case @expr
      when 'default'
        r.last << @expr
      else
        r.last << 'case '
        r, dep = CExpression.dump(@expr, scope, r, dep)
        if exprup
          r.last << ' ... '
          r, dep = CExpression.dump(@exprup, scope, r, dep)
        end
      end
      r.last << ':'
      dump_inner(scope, r, dep)
    end

    def self.dump_indent(s, short=false)
      case s
      when /^(case|default)\W/; (short ? '    ' : "\t") << s
      when /^\s+(case|default)\W/; "\t" << s
      when /:$/; s
      else "\t" << s
      end
    end
  end
  class Label
    def dump(scope, r=[''], dep=[])
      r.last << @name << ':'
      dump_inner(scope, r, dep)
    end
    def dump_inner(scope, r=[''], dep=[])
      if not @statement; [r, dep]
      elsif @statement.kind_of? Block; Statement.dump(@statement, scope, r, dep)
      else  @statement.dump(scope, r << '', dep)
      end
    end
  end
  class Asm
    def dump(scope, r=[''], dep=[])
      r.last << 'asm '
      r.last << 'volatile ' if @volatile
      r.last << '('
      r.last << CExpression.string_inspect(@body)
      if @output or @input or @clobber
        if @output and @output != []
          # TODO
          r << ': /* todo */'
        elsif (@input and @input != []) or (@clobber and @clobber != [])
          r.last << ' :'
        end
      end
      if @input or @clobber
        if @input and @input != []
          # TODO
          r << ': /* todo */'
        elsif @clobber and @clobber != []
          r.last << ' :'
        end
      end
      if @clobber and @clobber != []
        r << (': ' << @clobber.map { |c| CExpression.string_inspect(c) }.join(', '))
      end
      r.last << ');'
      [r, dep]
    end
  end
  class CExpression
    def self.string_inspect(s)
      # keep all ascii printable except \ and "
      '"' + s.gsub(/[^ !\x23-\x5b\x5d-\x7e]/) { |o| '\\x' + o.unpack('H*').first } + '"'
    end

    def self.dump(e, scope, r=[''], dep=[], brace = false)
      if $DEBUG
        brace = false
        case e
        when CExpression, Variable
          r, dep = e.type.dump_cast(scope, r, dep)
        end
        r.last << '('
      end
      r, dep = \
      case e
      when ::Numeric; r.last << e.to_s ; [r, dep]
      when ::String; r.last << string_inspect(e) ; [r, dep]
      when CExpression; e.dump_inner(scope, r, dep, brace)
      when Variable; e.dump(scope, r, dep)
      when nil; [r, dep]
      else raise 'wtf?' + e.inspect
      end
      if $DEBUG
        r.last << ')'
      end
      [r, dep]
    end

    def dump(scope, r=[''], dep=[])
      r, dep = dump_inner(scope, r, dep)
      r.last << ';'
      [r, dep]
    end

    def dump_inner(scope, r=[''], dep=[], brace = false)
      r.last << '(' if brace and @op != :'->' and @op != :'.' and @op != :'[]' and (@op or @rexpr.kind_of? CExpression)
      if not @lexpr
        if not @op
          case @rexpr
          when ::Numeric
            if @rexpr < 0
              r.last << ?-
              re = -@rexpr
            else
              re = @rexpr
            end
            if re >= 0x1000
              r.last << ("0x%X" % re)
            else
              r.last << re.to_s
            end
            if @type.kind_of? BaseType
              r.last << 'U' if @type.specifier == :unsigned
              case @type.name
              when :longlong, :__int64; r.last << 'LL'
              when :long, :longdouble; r.last << 'L'
              when :float; r.last << 'F'
              end
            end
          when ::String
            r.last << 'L' if @type.kind_of? Pointer and @type.type.kind_of? BaseType and @type.type.name == :short
            r.last << CExpression.string_inspect(@rexpr)
          when CExpression # cast
            r, dep = @type.dump_cast(scope, r, dep)
            r, dep = CExpression.dump(@rexpr, scope, r, dep, true)
          when Variable
            r, dep = @rexpr.dump(scope, r, dep)
          when Block
            r.last << '('
            r, dep = Statement.dump(@rexpr, scope, r, dep)
            r.last << ' )'
          when Label
            r.last << '&&' << @rexpr.name
          else raise "wtf? #{inspect}"
          end
        else
          r.last << @op.to_s
          r, dep = CExpression.dump(@rexpr, scope, r, dep, (@rexpr.kind_of? C::CExpression and @rexpr.lexpr))
        end
      elsif not @rexpr
        r, dep = CExpression.dump(@lexpr, scope, r, dep)
        r.last << @op.to_s
      else
        case @op
        when :'->', :'.'
          r, dep = CExpression.dump(@lexpr, scope, r, dep, true)
          r.last << @op.to_s << @rexpr
        when :'[]'
          r, dep = CExpression.dump(@lexpr, scope, r, dep, true)
          r.last << '['
          l = lexpr if lexpr.kind_of? Variable
          l = lexpr.lexpr.type.untypedef.findmember(lexpr.rexpr) if lexpr.kind_of? CExpression and lexpr.op == :'.'
          l = lexpr.lexpr.type.pointed.untypedef.findmember(lexpr.rexpr) if lexpr.kind_of? CExpression and lexpr.op == :'->'
          # honor __attribute__((indexenum(enumname)))
          if l and l.attributes and rexpr.kind_of? CExpression and not rexpr.op and rexpr.rexpr.kind_of? ::Integer and
              n = l.has_attribute_var('indexenum') and enum = scope.struct_ancestors[n] and i = enum.members.index(rexpr.rexpr)
            r.last << i
            dep |= [enum]
          else
            r, dep = CExpression.dump(@rexpr, scope, r, dep)
          end
          r.last << ']'
        when :funcall
          r, dep = CExpression.dump(@lexpr, scope, r, dep, true)
          r.last << '('
          @rexpr.each { |arg|
            r.last << ', ' if r.last[-1] != ?(
            r, dep = CExpression.dump(arg, scope, r, dep)
          }
          r.last << ')'
        when :'?:'
          r, dep = CExpression.dump(@lexpr, scope, r, dep, true)
          r.last << ' ? '
          r, dep = CExpression.dump(@rexpr[0], scope, r, dep, true)
          r.last << ' : '
          r, dep = CExpression.dump(@rexpr[1], scope, r, dep, true)
        else
          r, dep = CExpression.dump(@lexpr, scope, r, dep, (@lexpr.kind_of? CExpression and @lexpr.lexpr and @lexpr.op != @op))
          r.last << ' ' << @op.to_s << ' '
          r, dep = CExpression.dump(@rexpr, scope, r, dep, (@rexpr.kind_of? CExpression and @rexpr.lexpr and @rexpr.op != @op and @rexpr.op != :funcall))
        end
      end
      r.last << ')' if brace and @op != :'->' and @op != :'.' and @op != :'[]' and (@op or @rexpr.kind_of? CExpression)
      [r, dep]
    end

    def to_s
      dump_inner(Block.new(nil))[0].join(' ')
    end
  end
end
end
