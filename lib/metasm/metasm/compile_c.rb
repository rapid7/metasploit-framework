#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/parse_c'

module Metasm
module C
  class Parser
    def precompile
      @toplevel.precompile(Compiler.new(self, @program))
      self
    end
  end

  # each CPU defines a subclass of this one
  class Compiler
    # an ExeFormat (mostly used for unique label creation, and cpu.check_reserved_name)
    attr_accessor :exeformat
    # the C Parser (destroyed by compilation)
    attr_accessor :parser
    # an array of assembler statements (strings)
    attr_accessor :source
    # list of unique labels generated (to recognize user-defined ones)
    attr_accessor :auto_label_list
    # map asm name -> original C name (for exports etc)
    attr_accessor :label_oldname

    attr_accessor :curexpr
    # allows 'raise self' (eg struct.offsetof)
    def exception(msg='EOF unexpected')
      ParseError.new "near #@curexpr: #{msg}"
    end

    # creates a new CCompiler from an ExeFormat and a C Parser
    def initialize(parser, exeformat=nil, source=[])
      exeformat ||= ExeFormat.new
      @parser, @exeformat, @source = parser, exeformat, source
      @auto_label_list = {}
      @label_oldname = {}
    end

    def new_label(base='')
      lbl = @exeformat.new_label base
      @auto_label_list[lbl] = true
      lbl
    end

    def toplevel ; @parser.toplevel end
    def typesize ; @parser.typesize end
    def sizeof(*a) @parser.sizeof(*a) end

    # compiles the c parser toplevel to assembler statements in self.source (::Array of ::String)
    #
    # starts by precompiling parser.toplevel (destructively):
    # static symbols are converted to toplevel ones, as nested functions
    # uses an ExeFormat (the argument) to create unique label/variable names
    #
    # remove typedefs/enums
    # CExpressions: all expr types are converted to __int8/__int16/__int32/__int64 (sign kept) (incl. ptr), + void
    #  struct member dereference/array indexes are converted to *(ptr + off)
    #  coma are converted to 2 statements, ?: are converted to If
    #  :|| and :&& are converted to If + assignment to temporary
    #  immediate quotedstrings/floats are converted to references to const static toplevel
    #  postincrements are replaced by a temporary (XXX arglist)
    #  compound statements are unnested
    # Asm are kept (TODO precompile clobber types)
    # Declarations: initializers are converted to separate assignment CExpressions
    # Blocks are kept unless empty
    # structure dereferences/array indexing are converted to *(ptr + offset)
    # While/For/DoWhile/Switch are converted to If/Goto
    # Continue/Break are converted to Goto
    # Cases are converted to Labels during Switch conversion
    # Label statements are removed
    # Return: 'return <foo>;' => 'return <foo>; goto <end_of_func>;', 'return;' => 'goto <eof>;'
    # If: 'if (a) b; else c;' => 'if (a) goto l1; { c; }; goto l2; l1: { b; } l2:'
    #  && and || in condition are expanded to multiple If
    # functions returning struct are precompiled (in Declaration/CExpression/Return)
    #
    # in a second phase, unused labels are removed from functions, as noop goto (goto x; x:)
    # dead code is removed ('goto foo; bar; baz:' => 'goto foo; baz:') (TODO)
    #
    # after that, toplevel is no longer valid C (bad types, blocks moved...)
    #
    # then toplevel statements are sorted (.text, .data, .rodata, .bss) and compiled into asm statements in self.source
    #
    # returns the asm source in a single string
    def compile
      cf = @exeformat.unique_labels_cache.keys & @auto_label_list.keys
      raise "compile_c name conflict: #{cf.inspect}" if not cf.empty?
      @exeformat.unique_labels_cache.update @auto_label_list

      @parser.toplevel.precompile(self)

      # reorder statements (arrays of Variables) following exe section typical order
      funcs, rwdata, rodata, udata = [], [], [], []
      @parser.toplevel.statements.each { |st|
        if st.kind_of? Asm
          @source << st.body
          next
        end
        raise 'non-declaration at toplevel! ' + st.inspect if not st.kind_of? Declaration
        v = st.var
        if v.type.kind_of? Function
          funcs << v if v.initializer	# no initializer == storage :extern
        elsif v.storage == :extern
        elsif v.initializer
          if v.type.qualifier.to_a.include?(:const) or
          (v.type.kind_of? Array and v.type.type.qualifier.to_a.include?(:const))
            rodata << v
          else
            rwdata << v
          end
        else
          udata << v
        end
      }

      if not funcs.empty?
        @exeformat.compile_setsection @source, '.text'
        funcs.each { |func| c_function(func) }
        c_program_epilog
      end

      align = 1
      if not rwdata.empty?
        @exeformat.compile_setsection @source, '.data'
        rwdata.each { |data| align = c_idata(data, align) }
      end

      if not rodata.empty?
        @exeformat.compile_setsection @source, '.rodata'
        rodata.each { |data| align = c_idata(data, align) }
      end

      if not udata.empty?
        @exeformat.compile_setsection @source, '.bss'
        udata.each  { |data| align = c_udata(data, align) }
      end

      # needed to allow asm parser to use our autogenerated label names
      @exeformat.unique_labels_cache.delete_if { |k, v| @auto_label_list[k] }

      @source.join("\n")
    end

    # compiles a C function +func+ to asm source into the array of strings +str+
    # in a first pass the stack variable offsets are computed,
    # then each statement is compiled in turn
    def c_function(func)
      # must wait the Declaration to run the CExpr for dynamic auto offsets,
      # and must run those statements once only
      # TODO alloc a stack variable to maintain the size for each dynamic array
      # TODO offset of arguments
      # TODO nested function
      c_init_state(func)

      # hide the full @source while compiling, then add prolog/epilog (saves 1 pass)
      @source << ''
      @source << "#{@label_oldname[func.name]}:" if @label_oldname[func.name]
      @source << "#{func.name}:"
      presource, @source = @source, []

      c_block(func.initializer)

      tmpsource, @source = @source, presource
      c_prolog
      @source.concat tmpsource
      c_epilog
      @source << ''
    end

    def c_block(blk)
      c_block_enter(blk)
      blk.statements.each { |stmt|
        case stmt
        when CExpression; c_cexpr(stmt)
        when Declaration; c_decl(stmt.var)
        when If; c_ifgoto(stmt.test, stmt.bthen.target)
        when Goto; c_goto(stmt.target)
        when Label; c_label(stmt.name)
        when Return; c_return(stmt.value)
        when Asm; c_asm(stmt)
        when Block; c_block(stmt)
        else raise
        end
      }
      c_block_exit(blk)
    end

    def c_block_enter(blk)
    end

    def c_block_exit(blk)
    end

    def c_label(name)
      @source << "#{name}:"
    end

    # fills @state.offset (empty hash)
    # automatic variable => stack offset, (recursive)
    # offset is an ::Integer or a CExpression (dynamic array)
    # assumes offset 0 is a ptr-size-aligned address
    # TODO registerize automatic variables
    def c_reserve_stack(block, off = 0)
      block.statements.each { |stmt|
        case stmt
        when Declaration
          next if stmt.var.type.kind_of? Function
          off = c_reserve_stack_var(stmt.var, off)
          @state.offset[stmt.var] = off
        when Block
          c_reserve_stack(stmt, off)
          # do not update off, not nested subblocks can overlap
        end
      }
    end

    # computes the new stack offset for var
    # off is either an offset from stack start (:ptr-size-aligned) or
    #  a CExpression [[[expr, +, 7], &, -7], +, off]
    def c_reserve_stack_var(var, off)
      if (arr_type = var.type).kind_of? Array and (arr_sz = arr_type.length).kind_of? CExpression
        # dynamic array !
        arr_sz = CExpression.new(arr_sz, :*, sizeof(nil, arr_type.type),
                 BaseType.new(:long, :unsigned)).precompile_inner(@parser, nil)
        off = CExpression.new(arr_sz, :+, off, arr_sz.type)
        off = CExpression.new(off, :+,  7, off.type)
        off = CExpression.new(off, :&, -7, off.type)
        CExpression.new(off, :+,  0, off.type)
      else
        al = var.type.align(@parser)
        sz = sizeof(var)
        case off
        when CExpression; CExpression.new(off.lexpr, :+, ((off.rexpr + sz + al - 1) / al * al), off.type)
        else (off + sz + al - 1) / al * al
        end
      end
    end

    # here you can add thing like stubs for PIC code
    def c_program_epilog
    end

    # compiles a C static data definition into an asm string
    # returns the new alignment value
    def c_idata(data, align)
      w = data.type.align(@parser)
      @source << ".align #{align = w}" if w > align

      @source << "#{@label_oldname[data.name]}:" if @label_oldname[data.name]
      @source << data.name.dup
      len = c_idata_inner(data.type, data.initializer)
      len %= w
      len == 0 ? w : len
    end

    # dumps an anonymous variable definition, appending to the last line of source
    # source.last is a label name or is empty before calling here
    # return the length of the data written
    def c_idata_inner(type, value)
      case type
      when BaseType
        value ||= 0

        if type.name == :void
          @source.last << ':' if not @source.last.empty?
          return 0
        end

        @source.last <<
        case type.name
        when :__int8;  ' db '
        when :__int16; ' dw '
        when :__int32; ' dd '
        when :__int64; ' dq '
        when :ptr; " d#{%w[x b w x d x x x q][@parser.typesize[type.name]]} "
        when :float;   ' db ' + [value].pack(@parser.endianness == :little ? 'e' : 'g').unpack('C*').join(', ') + ' // '
        when :double;  ' db ' + [value].pack(@parser.endianness == :little ? 'E' : 'G').unpack('C*').join(', ') + ' // '
        when :longdouble; ' db ' + [value].pack(@parser.endianness == :little ? 'E' : 'G').unpack('C*').join(', ') + ' // '	# XXX same as :double
        else raise "unknown idata type #{type.inspect} #{value.inspect}"
        end

        @source.last << c_idata_inner_cexpr(value)

        @parser.typesize[type.name]

      when Struct
        value ||= []
        @source.last << ':' if not @source.last.empty?
        # could .align here, but if there is our label name just before, it should have been .aligned too..
        raise "unknown struct initializer #{value.inspect}" if not value.kind_of? ::Array
        sz = 0
        type.members.zip(value).each { |m, v|
          if m.name and wsz = type.offsetof(@parser, m.name) and sz < wsz
            @source << "db #{wsz-sz} dup(?)"
          end
          @source << ''
          flen = c_idata_inner(m.type, v)
          sz += flen
        }

        sz

      when Union
        value ||= []
        @source.last << ':' if not @source.last.empty?
        len = sizeof(nil, type)
        raise "unknown union initializer #{value.inspect}" if not value.kind_of? ::Array
        idx = value.rindex(value.compact.last) || 0
        raise "empty union initializer" if not idx
        wlen = c_idata_inner(type.members[idx].type, value[idx])
        @source << "db #{'0' * (len - wlen) * ', '}" if wlen < len

        len

      when Array
        value ||= []
        if value.kind_of? CExpression and not value.op and value.rexpr.kind_of? ::String
          elen = sizeof(nil, value.type.type)
          @source.last <<
          case elen
          when 1; ' db '
          when 2; ' dw '
          else raise 'bad char* type ' + value.inspect
          end << value.rexpr.inspect

          len = type.length || (value.rexpr.length+1)
          if len > value.rexpr.length
            @source.last << (', 0' * (len - value.rexpr.length))
          end

          elen * len

        elsif value.kind_of? ::Array
          @source.last << ':' if not @source.last.empty?
          len = type.length || value.length
          value.each { |v|
            @source << ''
            c_idata_inner(type.type, v)
          }
          len -= value.length
          if len > 0
            @source << " db #{len * sizeof(nil, type.type)} dup(0)"
          end

          sizeof(nil, type.type) * len

        else raise "unknown static array initializer #{value.inspect}"
        end
      end
    end

    def c_idata_inner_cexpr(expr)
      expr = expr.reduce(@parser) if expr.kind_of? CExpression
      case expr
      when ::Integer; (expr >= 4096) ? ('0x%X' % expr) : expr.to_s
      when ::Numeric; expr.to_s
      when Variable
        case expr.type
        when Array; expr.name
        else c_idata_inner_cexpr(expr.initializer)
        end
      when CExpression
        if not expr.lexpr
          case expr.op
          when :&
            case expr.rexpr
            when Variable; expr.rexpr.name
            else raise 'unhandled addrof in initializer ' + expr.rexpr.inspect
            end
          #when :*
          when :+; c_idata_inner_cexpr(expr.rexpr)
          when :-; ' -' << c_idata_inner_cexpr(expr.rexpr)
          when nil
            e = c_idata_inner_cexpr(expr.rexpr)
            if expr.rexpr.kind_of? CExpression
              e = '(' << e << " & 0#{'ff'*sizeof(expr)}h)"
            end
            e
          else raise 'unhandled initializer expr ' + expr.inspect
          end
        else
          case expr.op
          when :+, :-, :*, :/, :%, :<<, :>>, :&, :|, :^
            e = '(' << c_idata_inner_cexpr(expr.lexpr) <<
            expr.op.to_s << c_idata_inner_cexpr(expr.rexpr) << ')'
            if expr.type.integral?
              # db are unsigned
              e = '(' << e << " & 0#{'ff'*sizeof(expr)}h)"
            end
            e
          #when :'.'
          #when :'->'
          #when :'[]'
          else raise 'unhandled initializer expr ' + expr.inspect
          end
        end
      else raise 'unhandled initializer ' + expr.inspect
      end
    end

    def c_udata(data, align)
      @source << "#{@label_oldname[data.name]}:" if @label_oldname[data.name]
      @source << "#{data.name} "
      @source.last <<
      case data.type
      when BaseType
        len = @parser.typesize[data.type.name]
        case data.type.name
        when :__int8;  'db ?'
        when :__int16; 'dw ?'
        when :__int32; 'dd ?'
        when :__int64; 'dq ?'
        else "db #{len} dup(?)"
        end
      else
        len = sizeof(data)
        "db #{len} dup(?)"
      end
      len %= align
      len == 0 ? align : len
    end

    # return non-nil if the variable name is unsuitable to appear as is in the asm listing
    # eg filter out asm instruction names
    def check_reserved_name(var)
      return true if @exeformat.cpu and @exeformat.cpu.check_reserved_name(var.name)
      %w[db dw dd dq].include?(var.name)
    end
  end

  class Statement
    # all Statements/Declaration must define a precompile(compiler, scope) method
    # it must append itself to scope.statements

    # turns a statement into a new block
    def precompile_make_block(scope)
      b = Block.new scope
      b.statements << self
      b
    end
  end

  class Block
    # precompile all statements, then simplifies symbols/structs types
    def precompile(compiler, scope=nil)
      stmts = @statements.dup
      @statements.clear
      stmts.each { |st|
        compiler.curexpr = st
        st.precompile(compiler, self)
      }

      # cleanup declarations
      @symbol.delete_if { |n, s| not s.kind_of? Variable }
      @struct.delete_if { |n, s| not s.kind_of? Union }
      @symbol.each_value { |var|
        CExpression.precompile_type(compiler, self, var, true)
      }
      @struct.each_value { |var|
        next if not var.members
        var.members.each { |m|
          CExpression.precompile_type(compiler, self, m, true)
        }
      }
      scope.statements << self if scope and not @statements.empty?
    end

    # removes unused labels, and in-place goto (goto toto; toto:)
    def precompile_optimize
      list = []
      precompile_optimize_inner(list, 1)
      precompile_optimize_inner(list, 2)
    end

    # step 1: list used labels/unused goto
    # step 2: remove unused labels
    def precompile_optimize_inner(list, step)
      lastgoto = nil
      hadref = false
      walk = lambda { |expr|
        next if not expr.kind_of? CExpression
        # gcc's unary && support
        if not expr.op and not expr.lexpr and expr.rexpr.kind_of? Label
          list << expr.rexpr.name
        else
          walk[expr.lexpr]
          if expr.rexpr.kind_of? ::Array
            expr.rexpr.each { |r| walk[r] }
          else
            walk[expr.rexpr]
          end
        end
      }
      @statements.dup.each { |s|
        lastgoto = nil if not s.kind_of? Label
        case s
        when Block
          s.precompile_optimize_inner(list, step)
          @statements.delete s if step == 2 and s.statements.empty?
        when CExpression; walk[s] if step == 1
        when Label
          case step
          when 1
            if lastgoto and lastgoto.target == s.name
              list << lastgoto
              list.delete s.name if not hadref
            end
          when 2; @statements.delete s if not list.include? s.name
          end
        when Goto, If
          s.kind_of?(If) ? g = s.bthen : g = s
          case step
          when 1
            hadref = list.include? g.target
            lastgoto = g
            list << g.target
          when 2
            if list.include? g
              idx = @statements.index s
              @statements.delete s
              @statements[idx, 0] = s.test if s != g and not s.test.constant?
            end
          end
        end
      }
      list
    end

    # noop
    def precompile_make_block(scope) self end

    def continue_label ; defined?(@continue_label) ? @continue_label : @outer.continue_label end
    def continue_label=(l) @continue_label = l end
    def break_label ; defined?(@break_label) ? @break_label : @outer.break_label end
    def break_label=(l) @break_label = l end
    def return_label ; defined?(@return_label) ? @return_label : @outer.return_label end
    def return_label=(l) @return_label = l end
    def nonauto_label=(l) @nonauto_label = l end
    def nonauto_label ; defined?(@nonauto_label) ? @nonauto_label : @outer.nonauto_label end
    def function ; defined?(@function) ? @function : @outer.function end
    def function=(f) @function = f end
  end

  class Declaration
    def precompile(compiler, scope)
      if (@var.type.kind_of? Function and @var.initializer and scope != compiler.toplevel) or @var.storage == :static or compiler.check_reserved_name(@var)
        old = @var.name
        ref = scope.symbol.delete old
        if scope == compiler.toplevel or (@var.type.kind_of?(Function) and not @var.initializer)
          if n = compiler.label_oldname.index(old)
            # reuse same name as predeclarations
            @var.name = n
          else
            newname = old
            newname = compiler.new_label newname until newname != old
            if not compiler.check_reserved_name(@var)
              compiler.label_oldname[newname] = old
            end
            @var.name = newname
          end
          ref ||= scope.symbol[@var.name] || @var
          # append only one actual declaration for all predecls (the one with init, or the last uninit)
          scope.statements << self if ref.eql?(@var)
        else
          @var.name = compiler.new_label @var.name until @var.name != old
          compiler.toplevel.statements << self
        end
        compiler.toplevel.symbol[@var.name] = ref
      else
        scope.symbol[@var.name] ||= @var
        appendme = true if scope.symbol[@var.name].eql?(@var)
      end

      if i = @var.initializer
        if @var.type.kind_of? Function
          if @var.type.type.kind_of? Union
            s = @var.type.type
            v = Variable.new
            v.name = compiler.new_label('return_struct_ptr')
            v.type = Pointer.new(s)
            CExpression.precompile_type(compiler, scope, v)
            @var.type.args.unshift v
            @var.type.type = v.type
          end
          i.function = @var
          i.return_label = compiler.new_label('epilog')
          i.nonauto_label = {}
          i.precompile(compiler)
          Label.new(i.return_label).precompile(compiler, i)
          i.precompile_optimize
          # append now so that static dependencies are declared before us
          # TODO no pure inline if addrof(func) needed
          scope.statements << self if appendme and not @var.attributes.to_a.include? 'inline'
        elsif scope != compiler.toplevel and @var.storage != :static
          scope.statements << self if appendme
          Declaration.precompile_dyn_initializer(compiler, scope, @var, @var.type, i)
          @var.initializer = nil
        else
          scope.statements << self if appendme
          @var.initializer = Declaration.precompile_static_initializer(compiler, @var.type, i)
        end
      else
        scope.statements << self if appendme
      end
    end

    # turns an initializer to CExpressions in scope.statements
    def self.precompile_dyn_initializer(compiler, scope, var, type, init)
      case type = type.untypedef
      when Array
        # XXX TODO type.length may be dynamic !!
        case init
        when CExpression
          # char toto[] = "42"
          if not init.kind_of? CExpression or init.op or init.lexpr or not init.rexpr.kind_of? ::String
            raise "unknown initializer #{init.inspect} for #{var.inspect}"
          end
          init = init.rexpr.unpack('C*') + [0]
          init.map! { |chr| CExpression.new(nil, nil, chr, type.type) }
          precompile_dyn_initializer(compiler, scope, var, type, init)

        when ::Array
          type.length ||= init.length
          # len is an Integer
          init.each_with_index { |it, idx|
            next if not it
            break if idx >= type.length
            idx = CExpression.new(nil, nil, idx, BaseType.new(:long, :unsigned))
            v = CExpression.new(var, :'[]', idx, type.type)
            precompile_dyn_initializer(compiler, scope, v, type.type, it)
          }
        else raise "unknown initializer #{init.inspect} for #{var.inspect}"
        end
      when Union
        case init
        when CExpression, Variable
          if init.type.untypedef.kind_of? BaseType
            # works for struct foo bar[] = {0}; ...
            type.members.each { |m|
              v = CExpression.new(var, :'.', m.name, m.type)
              precompile_dyn_initializer(compiler, scope, v, v.type, init)
            }
          elsif init.type.untypedef.kind_of? type.class
            CExpression.new(var, :'=', init, type).precompile(compiler, scope)
          else
            raise "bad initializer #{init.inspect} for #{var.inspect}"
          end
        when ::Array
          init.each_with_index{ |it, idx|
            next if not it
            m = type.members[idx]
            v = CExpression.new(var, :'.', m.name, m.type)
            precompile_dyn_initializer(compiler, scope, v, m.type, it)
          }
        else raise "unknown initializer #{init.inspect} for #{var.inspect}"
        end
      else
        case init
        when CExpression
          CExpression.new(var, :'=', init, type).precompile(compiler, scope)
        else raise "unknown initializer #{init.inspect} for #{var.inspect}"
        end
      end
    end

    # returns a precompiled static initializer (eg string constants)
    def self.precompile_static_initializer(compiler, type, init)
      # TODO
      case type = type.untypedef
      when Array
        if init.kind_of? ::Array
          init.map { |i| precompile_static_initializer(compiler, type.type, i) }
        else
          init
        end
      when Union
        if init.kind_of? ::Array
          init.zip(type.members).map { |i, m| precompile_static_initializer(compiler, m.type, i) }
        else
          init
        end
      else
        if init.kind_of? CExpression and init = init.reduce(compiler) and init.kind_of? CExpression
          if not init.op and init.rexpr.kind_of? ::String
            v = Variable.new
            v.storage = :static
            v.name = 'char_' + init.rexpr.gsub(/[^a-zA-Z]/, '')[0, 8]
            v.type = Array.new(type.type)
            v.type.length = init.rexpr.length + 1
            v.type.type.qualifier = [:const]
            v.initializer = CExpression.new(nil, nil, init.rexpr, type)
            Declaration.new(v).precompile(compiler, compiler.toplevel)
            init.rexpr = v
          end
          init.rexpr = precompile_static_initializer(compiler, init.rexpr.type, init.rexpr) if init.rexpr.kind_of? CExpression
          init.lexpr = precompile_static_initializer(compiler, init.lexpr.type, init.lexpr) if init.lexpr.kind_of? CExpression
        end
        init
      end
    end
  end

  class If
    def precompile(compiler, scope)
      expr = lambda { |e| e.kind_of?(CExpression) ? e : CExpression.new(nil, nil, e, e.type) }

      if @bthen.kind_of? Goto or @bthen.kind_of? Break or @bthen.kind_of? Continue
        # if () goto l; else b; => if () goto l; b;
        if belse
          t1 = @belse
          @belse = nil
        end

        # need to convert user-defined Goto target !
        @bthen.precompile(compiler, scope)
        @bthen = scope.statements.pop	# break => goto break_label
      elsif belse
        # if () a; else b; => if () goto then; b; goto end; then: a; end:
        t1 = @belse
        t2 = @bthen
        l2 = compiler.new_label('if_then')
        @bthen = Goto.new(l2)
        @belse = nil
        l3 = compiler.new_label('if_end')
      else
        # if () a; => if (!) goto end; a; end:
        t1 = @bthen
        l2 = compiler.new_label('if_end')
        @bthen = Goto.new(l2)
        @test = CExpression.negate(@test)
      end

      @test = expr[@test]
      case @test.op
      when :'&&'
        # if (c1 && c2) goto a; => if (!c1) goto b; if (c2) goto a; b:
        l1 = compiler.new_label('if_nand')
        If.new(CExpression.negate(@test.lexpr), Goto.new(l1)).precompile(compiler, scope)
        @test = expr[@test.rexpr]
        precompile(compiler, scope)
      when :'||'
        l1 = compiler.new_label('if_or')
        If.new(expr[@test.lexpr], Goto.new(@bthen.target)).precompile(compiler, scope)
        @test = expr[@test.rexpr]
        precompile(compiler, scope)
      else
        @test = CExpression.precompile_inner(compiler, scope, @test)
        t = @test.reduce(compiler)
        if t.kind_of? ::Integer
          if t == 0
            Label.new(l1, nil).precompile(compiler, scope) if l1
            t1.precompile(compiler, scope) if t1
            Label.new(l2, nil).precompile(compiler, scope) if l2
            Label.new(l3, nil).precompile(compiler, scope) if l3
          else
            scope.statements << @bthen
            Label.new(l1, nil).precompile(compiler, scope) if l1
            Label.new(l2, nil).precompile(compiler, scope) if l2
            t2.precompile(compiler, scope) if t2
            Label.new(l3, nil).precompile(compiler, scope) if l3
          end
          return
        end
        scope.statements << self
      end

      Label.new(l1, nil).precompile(compiler, scope) if l1
      t1.precompile(compiler, scope) if t1
      Goto.new(l3).precompile(compiler, scope) if l3
      Label.new(l2, nil).precompile(compiler, scope) if l2
      t2.precompile(compiler, scope) if t2
      Label.new(l3, nil).precompile(compiler, scope) if l3
    end
  end

  class For
    def precompile(compiler, scope)
      if init
        @init.precompile(compiler, scope)
        scope = @init if @init.kind_of? Block
      end

      @body = @body.precompile_make_block scope
      @body.continue_label = compiler.new_label 'for_continue'
      @body.break_label = compiler.new_label 'for_break'
      label_test = compiler.new_label 'for_test'

      Label.new(label_test).precompile(compiler, scope)
      if test
        If.new(CExpression.negate(@test), Goto.new(@body.break_label)).precompile(compiler, scope)
      end

      @body.precompile(compiler, scope)

      Label.new(@body.continue_label).precompile(compiler, scope)
      if iter
        @iter.precompile(compiler, scope)
      end

      Goto.new(label_test).precompile(compiler, scope)
      Label.new(@body.break_label).precompile(compiler, scope)
    end
  end

  class While
    def precompile(compiler, scope)
      @body = @body.precompile_make_block scope
      @body.continue_label = compiler.new_label('while_continue')
      @body.break_label = compiler.new_label('while_break')

      Label.new(@body.continue_label).precompile(compiler, scope)

      If.new(CExpression.negate(@test), Goto.new(@body.break_label)).precompile(compiler, scope)

      @body.precompile(compiler, scope)

      Goto.new(@body.continue_label).precompile(compiler, scope)
      Label.new(@body.break_label).precompile(compiler, scope)
    end
  end

  class DoWhile
    def precompile(compiler, scope)
      @body = @body.precompile_make_block scope
      @body.continue_label = compiler.new_label('dowhile_continue')
      @body.break_label = compiler.new_label('dowhile_break')
      loop_start = compiler.new_label('dowhile_start')

      Label.new(loop_start).precompile(compiler, scope)

      @body.precompile(compiler, scope)

      Label.new(@body.continue_label).precompile(compiler, scope)

      If.new(@test, Goto.new(loop_start)).precompile(compiler, scope)

      Label.new(@body.break_label).precompile(compiler, scope)
    end
  end

  class Switch
    def precompile(compiler, scope)
      var = Variable.new
      var.storage = :register
      var.name = compiler.new_label('switch')
      var.type = @test.type
      var.initializer = @test
      CExpression.precompile_type(compiler, scope, var)
      Declaration.new(var).precompile(compiler, scope)

      @body = @body.precompile_make_block scope
      @body.break_label = compiler.new_label('switch_break')
      @body.precompile(compiler)
      default = @body.break_label
      # recursive lambda to change Case to Labels
      # dynamically creates the If sequence
      walk = lambda { |blk|
        blk.statements.each_with_index { |s, i|
          case s
          when Case
            label = compiler.new_label('case')
            if s.expr == 'default'
              default = label
            elsif s.exprup
              If.new(CExpression.new(CExpression.new(var, :'>=', s.expr, BaseType.new(:int)), :'&&',
                    CExpression.new(var, :'<=', s.exprup, BaseType.new(:int)),
                    BaseType.new(:int)), Goto.new(label)).precompile(compiler, scope)
            else
              If.new(CExpression.new(var, :'==', s.expr, BaseType.new(:int)),
                Goto.new(label)).precompile(compiler, scope)
            end
            blk.statements[i] = Label.new(label)
          when Block
            walk[s]
          end
        }
      }
      walk[@body]
      Goto.new(default).precompile(compiler, scope)
      scope.statements << @body
      Label.new(@body.break_label).precompile(compiler, scope)
    end
  end

  class Continue
    def precompile(compiler, scope)
      Goto.new(scope.continue_label).precompile(compiler, scope)
    end
  end

  class Break
    def precompile(compiler, scope)
      Goto.new(scope.break_label).precompile(compiler, scope)
    end
  end

  class Return
    def precompile(compiler, scope)
      if @value
        @value = CExpression.new(nil, nil, @value, @value.type) if not @value.kind_of? CExpression
        if @value.type.untypedef.kind_of? Union
          @value = @value.precompile_inner(compiler, scope)
          func = scope.function.type
          CExpression.new(CExpression.new(nil, :*, func.args.first, @value.type), :'=', @value, @value.type).precompile(compiler, scope)
          @value = func.args.first
        else
          # cast to function return type
          @value = CExpression.new(nil, nil, @value, scope.function.type.type).precompile_inner(compiler, scope)
        end
        scope.statements << self
      end
      Goto.new(scope.return_label).precompile(compiler, scope)
    end
  end

  class Label
    def precompile(compiler, scope)
      if name and (not compiler.auto_label_list[@name])
        @name = scope.nonauto_label[@name] ||= compiler.new_label(@name)
      end
      scope.statements << self
      if statement
        @statement.precompile(compiler, scope)
        @statement = nil
      end
    end
  end

  class Case
    def precompile(compiler, scope)
      @expr = CExpression.precompile_inner(compiler, scope, @expr)
      @exprup = CExpression.precompile_inner(compiler, scope, @exprup) if exprup
      super(compiler, scope)
    end
  end

  class Goto
    def precompile(compiler, scope)
      if not compiler.auto_label_list[@target]
        @target = scope.nonauto_label[@target] ||= compiler.new_label(@target)
      end
      scope.statements << self
    end
  end

  class Asm
    def precompile(compiler, scope)
      scope.statements << self
      # TODO CExpr.precompile_type(clobbers)
    end
  end

  class CExpression
    def precompile(compiler, scope)
      i = precompile_inner(compiler, scope, false)
      scope.statements << i if i
    end

    # changes obj.type to a precompiled type
    # keeps struct/union, change everything else to __int\d
    # except Arrays if declaration is true (need to know variable allocation sizes etc)
    # returns the type
    def self.precompile_type(compiler, scope, obj, declaration = false)
      case t = obj.type.untypedef
      when BaseType
        case t.name
        when :void
        when :float, :double, :longdouble
        else t = BaseType.new("__int#{compiler.typesize[t.name]*8}".to_sym, t.specifier)
        end
      when Array
        if declaration; precompile_type(compiler, scope, t, declaration)
        else   t = BaseType.new("__int#{compiler.typesize[:ptr]*8}".to_sym, :unsigned)
        end
      when Pointer
        if t.type.untypedef.kind_of? Function
          precompile_type(compiler, scope, t, declaration)
        else
          t = BaseType.new("__int#{compiler.typesize[:ptr]*8}".to_sym, :unsigned)
        end
      when Enum;     t = BaseType.new("__int#{compiler.typesize[:int]*8}".to_sym)
      when Function
        precompile_type(compiler, scope, t)
        t.args ||= []
        t.args.each { |a| precompile_type(compiler, scope, a) }
      when Union
        if declaration and t.members and not t.name	# anonymous struct
          t.members.each { |a| precompile_type(compiler, scope, a, true) }
        end
      else raise 'bad type ' + t.inspect
      end
      (t.qualifier  ||= []).concat obj.type.qualifier  if obj.type.qualifier  and t != obj.type
      (t.attributes ||= []).concat obj.type.attributes if obj.type.attributes and t != obj.type
      while obj.type.kind_of? TypeDef
        obj.type = obj.type.type
        (t.qualifier  ||= []).concat obj.type.qualifier  if obj.type.qualifier  and t != obj.type
        (t.attributes ||= []).concat obj.type.attributes if obj.type.attributes and t != obj.type
      end
      obj.type = t
    end

    def self.precompile_inner(compiler, scope, expr, nested = true)
      case expr
      when CExpression; expr.precompile_inner(compiler, scope, nested)
      else expr
      end
    end

    # returns a new CExpression with simplified self.type, computes structure offsets
    # turns char[]/float immediates to reference to anonymised const
    # TODO 'a = b += c' => 'b += c; a = b' (use nested argument)
    # TODO handle precompile_inner return nil
    # TODO struct.bits
    def precompile_inner(compiler, scope, nested = true)
      case @op
      when :'.'
        # a.b => (&a)->b
        lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
        ll = lexpr
        ll = lexpr.rexpr while ll.kind_of? CExpression and not ll.op
        if ll.kind_of? CExpression and ll.op == :'*' and not ll.lexpr
          # do not change lexpr.rexpr.type directly to a pointer, might retrigger (ptr+imm) => (ptr + imm*sizeof(*ptr))
          @lexpr = CExpression.new(nil, nil, ll.rexpr, Pointer.new(lexpr.type))
        else
          @lexpr = CExpression.new(nil, :'&', lexpr, Pointer.new(lexpr.type))
        end
        @op = :'->'
        precompile_inner(compiler, scope)
      when :'->'
        # a->b => *(a + off(b))
        struct = @lexpr.type.untypedef.type.untypedef
        lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
        @lexpr = nil
        @op = nil
        if struct.kind_of? Union and (off = struct.offsetof(compiler, @rexpr)) != 0
          off = CExpression.new(nil, nil, off, BaseType.new(:int, :unsigned))
          @rexpr = CExpression.new(lexpr, :'+', off, lexpr.type)
          # ensure the (ptr + value) is not expanded to (ptr + value * sizeof(*ptr))
          CExpression.precompile_type(compiler, scope, @rexpr)
        else
          # union or 1st struct member
          @rexpr = lexpr
        end
        if @type.kind_of? Array # Array member type is already an address
        else
          @rexpr = CExpression.new(nil, :*, @rexpr, @rexpr.type)
        end
        precompile_inner(compiler, scope)
      when :'[]'
        rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
        if rexpr.kind_of? CExpression and not rexpr.op and rexpr.rexpr == 0
          @rexpr = @lexpr
        else
          @rexpr = CExpression.new(@lexpr, :'+', rexpr, @lexpr.type)
        end
        @op = :'*'
        @lexpr = nil
        precompile_inner(compiler, scope)
      when :'?:'
        # cannot precompile in place, a conditionnal expression may have a coma: must turn into If
        if @lexpr.kind_of? CExpression
          @lexpr = @lexpr.precompile_inner(compiler, scope)
          if not @lexpr.lexpr and not @lexpr.op and @lexpr.rexpr.kind_of? ::Numeric
            if @lexpr.rexpr == 0
              e = @rexpr[1]
            else
              e = @rexpr[0]
            end
            e = CExpression.new(nil, nil, e, e.type) if not e.kind_of? CExpression
            return e.precompile_inner(compiler, scope)
          end
        end
        raise 'conditional in toplevel' if scope == compiler.toplevel	# just in case
        var = Variable.new
        var.storage = :register
        var.name = compiler.new_label('ternary')
        var.type = @rexpr[0].type
        CExpression.precompile_type(compiler, scope, var)
        Declaration.new(var).precompile(compiler, scope)
        If.new(@lexpr, CExpression.new(var, :'=', @rexpr[0], var.type), CExpression.new(var, :'=', @rexpr[1], var.type)).precompile(compiler, scope)
        @lexpr = nil
        @op = nil
        @rexpr = var
        precompile_inner(compiler, scope)
      when :'&&'
        if scope == compiler.toplevel
          @lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          CExpression.precompile_type(compiler, scope, self)
          self
        else
          var = Variable.new
          var.storage = :register
          var.name = compiler.new_label('and')
          var.type = @type
          CExpression.precompile_type(compiler, scope, var)
          var.initializer = CExpression.new(nil, nil, 0, var.type)
          Declaration.new(var).precompile(compiler, scope)
          l = @lexpr.kind_of?(CExpression) ? @lexpr : CExpression.new(nil, nil, @lexpr, @lexpr.type)
          r = @rexpr.kind_of?(CExpression) ? @rexpr : CExpression.new(nil, nil, @rexpr, @rexpr.type)
          If.new(l, If.new(r, CExpression.new(var, :'=', CExpression.new(nil, nil, 1, var.type), var.type))).precompile(compiler, scope)
          @lexpr = nil
          @op = nil
          @rexpr = var
          precompile_inner(compiler, scope)
        end
      when :'||'
        if scope == compiler.toplevel
          @lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          CExpression.precompile_type(compiler, scope, self)
          self
        else
          var = Variable.new
          var.storage = :register
          var.name = compiler.new_label('or')
          var.type = @type
          CExpression.precompile_type(compiler, scope, var)
          var.initializer = CExpression.new(nil, nil, 1, var.type)
          Declaration.new(var).precompile(compiler, scope)
          l = @lexpr.kind_of?(CExpression) ? @lexpr : CExpression.new(nil, nil, @lexpr, @lexpr.type)
          l = CExpression.new(nil, :'!', l, var.type)
          r = @rexpr.kind_of?(CExpression) ? @rexpr : CExpression.new(nil, nil, @rexpr, @rexpr.type)
          r = CExpression.new(nil, :'!', r, var.type)
          If.new(l, If.new(r, CExpression.new(var, :'=', CExpression.new(nil, nil, 0, var.type), var.type))).precompile(compiler, scope)
          @lexpr = nil
          @op = nil
          @rexpr = var
          precompile_inner(compiler, scope)
        end
      when :funcall
        if @lexpr.kind_of? Variable and @lexpr.type.kind_of? Function and @lexpr.attributes and @lexpr.attributes.include? 'inline' and @lexpr.initializer
          # TODO check recursive call (direct or indirect)
          raise 'inline varargs unsupported' if @lexpr.type.varargs
          rtype = @lexpr.type.type.untypedef
          if not rtype.kind_of? BaseType or rtype.name != :void
            rval = Variable.new
            rval.name = compiler.new_label('inline_return')
            rval.type = @lexpr.type.type
            Declaration.new(rval).precompile(compiler, scope)
          end
          inline_label = {}
          locals = @lexpr.type.args.zip(@rexpr).inject({}) { |h, (fa, a)|
            h.update fa => CExpression.new(nil, nil, a, fa.type).precompile_inner(compiler, scope)
          }
          copy_inline_ce = lambda { |ce|
            case ce
            when CExpression; CExpression.new(copy_inline_ce[ce.lexpr], ce.op, copy_inline_ce[ce.rexpr], ce.type)
            when Variable; locals[ce] || ce
            when ::Array; ce.map { |e_| copy_inline_ce[e_] }
            else ce
            end
          }
          copy_inline = lambda { |stmt, scp|
            case stmt
            when Block
              b = Block.new(scp)
              stmt.statements.each { |s|
                s = copy_inline[s, b]
                b.statements << s if s
              }
              b
            when If;     If.new(copy_inline_ce[stmt.test], copy_inline[stmt.bthen, scp])		# re-precompile ?
            when Label;  Label.new(inline_label[stmt.name]  ||= compiler.new_label('inline_'+stmt.name))
            when Goto;   Goto.new(inline_label[stmt.target] ||= compiler.new_label('inline_'+stmt.target))
            when Return; CExpression.new(rval, :'=', copy_inline_ce[stmt.value], rval.type).precompile_inner(compiler, scp) if stmt.value
            when CExpression; copy_inline_ce[stmt]
            when Declaration
              nv = stmt.var.dup
              if nv.type.kind_of? Array and nv.type.length.kind_of? CExpression
                nv.type = Array.new(nv.type.type, copy_inline_ce[nv.type.length])	# XXX nested dynamic?
              end
              locals[stmt.var] = nv
              scp.symbol[nv.name] = nv
              Declaration.new(nv)
            else raise 'unexpected inline statement ' + stmt.inspect
            end
          }
          scope.statements << copy_inline[@lexpr.initializer, scope]		# body already precompiled
          CExpression.new(nil, nil, rval, rval.type).precompile_inner(compiler, scope)
        elsif @type.kind_of? Union
          var = Variable.new
          var.name = compiler.new_label('return_struct')
          var.type = @type
          Declaration.new(var).precompile(compiler, scope)
          @rexpr.unshift CExpression.new(nil, :&, var, Pointer.new(var.type))

          var2 = Variable.new
          var2.name = compiler.new_label('return_struct_ptr')
          var2.type = Pointer.new(@type)
          var2.storage = :register
          CExpression.precompile_type(compiler, scope, var2)
          Declaration.new(var2).precompile(compiler, scope)
          @type = var2.type
          CExpression.new(var2, :'=', self, var2.type).precompile(compiler, scope)

          CExpression.new(nil, :'*', var2, var.type).precompile_inner(compiler, scope)
        else
          t = @lexpr.type.untypedef
          t = t.type.untypedef if t.pointer?
          @lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
          types = t.args.map { |a| a.type }
          # cast args to func prototype
          @rexpr.map! { |e_| (types.empty? ? e_ : CExpression.new(nil, nil, e_, types.shift)).precompile_inner(compiler, scope) }
          CExpression.precompile_type(compiler, scope, self)
          self
        end
      when :','
        lexpr = @lexpr.kind_of?(CExpression) ? @lexpr : CExpression.new(nil, nil, @lexpr, @lexpr.type)
        rexpr = @rexpr.kind_of?(CExpression) ? @rexpr : CExpression.new(nil, nil, @rexpr, @rexpr.type)
        lexpr.precompile(compiler, scope)
        rexpr.precompile_inner(compiler, scope)
      when :'!'
        CExpression.precompile_type(compiler, scope, self)
        if @rexpr.kind_of?(CExpression)
          case @rexpr.op
          when :'<', :'>', :'<=', :'>=', :'==', :'!='
            @op = { :'<' => :'>=', :'>' => :'<=', :'<=' => :'>', :'>=' => :'<',
              :'==' => :'!=', :'!=' => :'==' }[@rexpr.op]
            @lexpr = @rexpr.lexpr
            @rexpr = @rexpr.rexpr
            precompile_inner(compiler, scope)
          when :'&&', :'||'
            @op = { :'&&' => :'||', :'||' => :'&&' }[@rexpr.op]
            @lexpr = CExpression.new(nil, :'!', @rexpr.lexpr, @type)
            @rexpr = CExpression.new(nil, :'!', @rexpr.rexpr, @type)
            precompile_inner(compiler, scope)
          when :'!'
            if @rexpr.rexpr.kind_of? CExpression
              @op = nil
              @rexpr = @rexpr.rexpr
            else
              @op = :'!='
              @lexpr = @rexpr.rexpr
              @rexpr = CExpression.new(nil, nil, 0, @lexpr.type)
            end
            precompile_inner(compiler, scope)
          else
            @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
            self
          end
        else
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          self
        end
      when :'++', :'--'
        if not @rexpr
          var = Variable.new
          var.storage = :register
          var.name = compiler.new_label('postincrement')
          var.type = @type
          Declaration.new(var).precompile(compiler, scope)
          CExpression.new(var, :'=', @lexpr, @type).precompile(compiler, scope)
          CExpression.new(nil, @op, @lexpr, @type).precompile(compiler, scope)
          @lexpr = nil
          @op = nil
          @rexpr = var
          precompile_inner(compiler, scope)
        elsif @type.pointer? and compiler.sizeof(nil, @type.untypedef.type.untypedef) != 1
          # ++ptr => ptr += sizeof(*ptr) (done in += precompiler)
          @op = { :'++' => :'+=', :'--' => :'-=' }[@op]
          @lexpr = @rexpr
          @rexpr = CExpression.new(nil, nil, 1, BaseType.new(:ptr, :unsigned))
          precompile_inner(compiler, scope)
        else
          CExpression.precompile_type(compiler, scope, self)
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          self
        end
      when :'='
        # handle structure assignment/array assignment
        case @lexpr.type.untypedef
        when Union
          # rexpr may be a :funcall
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          @lexpr.type.untypedef.members.zip(@rexpr.type.untypedef.members) { |m1, m2|
            # assume m1 and m2 are compatible
            v1 = CExpression.new(@lexpr, :'.', m1.name, m1.type)
            v2 = CExpression.new(@rexpr, :'.', m2.name, m1.type)
            CExpression.new(v1, :'=', v2, v1.type).precompile(compiler, scope)
          }
          # (foo = bar).toto
          @op = nil
          @rexpr = @lexpr
          @lexpr = nil
          @type = @rexpr.type
          precompile_inner(compiler, scope) if nested
        when Array
          if not len = @lexpr.type.untypedef.length
            @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
            # char toto[] = "bla"
            if @rexpr.kind_of? CExpression and not @rexpr.lexpr and not @rexpr.op and
                @rexpr.rexpr.kind_of? Variable and @rexpr.rexpr.type.kind_of? Array
              len = @rexpr.rexpr.type.length
            end
          end
          raise 'array initializer with no length !' if not len
          # TODO optimize...
          len.times { |i|
            i = CExpression.new(nil, nil, i, BaseType.new(:long, :unsigned))
            v1 = CExpression.new(@lexpr, :'[]', i, @lexpr.type.untypedef.type)
            v2 = CExpression.new(@rexpr, :'[]', i, v1.type)
            CExpression.new(v1, :'=', v2, v1.type).precompile(compiler, scope)
          }
          @op = nil
          @rexpr = @lexpr
          @lexpr = nil
          @type = @rexpr.type
          precompile_inner(compiler, scope) if nested
        else
          @lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
          @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)
          CExpression.precompile_type(compiler, scope, self)
          self
        end
      when nil
        case @rexpr
        when Block
          # compound statements
          raise 'compound statement in toplevel' if scope == compiler.toplevel	# just in case
          var = Variable.new
          var.storage = :register
          var.name = compiler.new_label('compoundstatement')
          var.type = @type
          CExpression.precompile_type(compiler, scope, var)
          Declaration.new(var).precompile(compiler, scope)
          if @rexpr.statements.last.kind_of? CExpression
            @rexpr.statements[-1] = CExpression.new(var, :'=', @rexpr.statements[-1], var.type)
            @rexpr.precompile(compiler, scope)
          end
          @rexpr = var
          precompile_inner(compiler, scope)
        when ::String
          # char[] immediate
          v = Variable.new
          v.storage = :static
          v.name = 'char_' + @rexpr.tr('^a-zA-Z', '')[0, 8]
          v.type = Array.new(@type.type)
          v.type.length = @rexpr.length + 1
          v.type.type.qualifier = [:const]
          v.initializer = CExpression.new(nil, nil, @rexpr, @type)
          Declaration.new(v).precompile(compiler, scope)
          @rexpr = v
          precompile_inner(compiler, scope)
        when ::Float
          # float immediate
          v = Variable.new
          v.storage = :static
          v.name = @type.untypedef.name.to_s
          v.type = @type
          v.type.qualifier = [:const]
          v.initializer = CExpression.new(nil, nil, @rexpr, @type)
          Declaration.new(v).precompile(compiler, scope)
          @rexpr = CExpression.new(nil, :'*', v, v.type)
          precompile_inner(compiler, scope)
        when CExpression
          # simplify casts
          CExpression.precompile_type(compiler, scope, self)
          # propagate type first so that __uint64 foo() { return -1 } => 0xffffffffffffffff
          @rexpr.type = @type if @rexpr.kind_of? CExpression and @rexpr.op == :- and not @rexpr.lexpr and @type.kind_of? BaseType and @type.name == :__int64	# XXX kill me
          @rexpr = @rexpr.precompile_inner(compiler, scope)
          if @type.kind_of? BaseType and @rexpr.type.kind_of? BaseType
            if @rexpr.type == @type
              # noop cast
              @lexpr, @op, @rexpr = @rexpr.lexpr, @rexpr.op, @rexpr.rexpr
            elsif not @rexpr.op and @type.integral? and @rexpr.type.integral?
              if @rexpr.rexpr.kind_of? ::Numeric and (val = reduce(compiler)).kind_of? ::Numeric
                @rexpr = val
              elsif compiler.typesize[@type.name] < compiler.typesize[@rexpr.type.name]
                # (char)(short)(int)(long)foo => (char)foo
                @rexpr = @rexpr.rexpr
              end
            end
          end
          self
        else
          CExpression.precompile_type(compiler, scope, self)
          self
        end
      else
        # int+ptr => ptr+int
        if @op == :+ and @lexpr and @lexpr.type.integral? and @rexpr.type.pointer?
          @rexpr, @lexpr = @lexpr, @rexpr
        end

        # handle pointer + 2 == ((char *)pointer) + 2*sizeof(*pointer)
        if @rexpr and [:'+', :'+=', :'-', :'-='].include? @op and
            @type.pointer? and @rexpr.type.integral?
          sz = compiler.sizeof(nil, @type.untypedef.type.untypedef)
          if sz != 1
            sz = CExpression.new(nil, nil, sz, @rexpr.type)
            @rexpr = CExpression.new(@rexpr, :'*', sz, @rexpr.type)
          end
        end

        # type promotion => cast
        case @op
        when :+, :-, :*, :/, :&, :|, :^, :%
            if @lexpr
          if @lexpr.type != @type
            @lexpr = CExpression.new(nil, nil, @lexpr, @lexpr.type) if not @lexpr.kind_of? CExpression
            @lexpr = CExpression.new(nil, nil, @lexpr, @type)
          end
          if @rexpr.type != @type
            @rexpr = CExpression.new(nil, nil, @rexpr, @rexpr.type) if not @rexpr.kind_of? CExpression
            @rexpr = CExpression.new(nil, nil, @rexpr, @type)
          end
            end
        when :>>, :<<
          # char => int
          if @lexpr.type != @type
            @lexpr = CExpression.new(nil, nil, @lexpr, @lexpr.type) if not @lexpr.kind_of? CExpression
            @lexpr = CExpression.new(nil, nil, @lexpr, @type)
          end
        when :'+=', :'-=', :'*=', :'/=', :'&=', :'|=', :'^=', :'%='
          if @rexpr.type != @lexpr.type
            @rexpr = CExpression.new(nil, nil, @rexpr, @rexpr.type) if not @rexpr.kind_of? CExpression
            @rexpr = CExpression.new(nil, nil, @rexpr, @type)
          end
        end

        @lexpr = CExpression.precompile_inner(compiler, scope, @lexpr)
        @rexpr = CExpression.precompile_inner(compiler, scope, @rexpr)

        if @op == :'&' and not @lexpr
          rr = @rexpr
          rr = rr.rexpr while rr.kind_of? CExpression and not rr.op
          if rr.kind_of? CExpression and rr.op == :'*' and not rr.lexpr
            @lexpr = nil
            @op = nil
            @rexpr = rr.rexpr
            return precompile_inner(compiler, scope)
          elsif rr != @rexpr
            @rexpr = rr
            return precompile_inner(compiler, scope)
          end
        end

        CExpression.precompile_type(compiler, scope, self)

        isnumeric = lambda { |e_| e_.kind_of?(::Numeric) or (e_.kind_of? CExpression and
          not e_.lexpr and not e_.op and e_.rexpr.kind_of? ::Numeric) }

        # calc numeric
        # XXX do not simplify operations involving variables (for type overflow etc)
        if isnumeric[@rexpr] and (not @lexpr or isnumeric[@lexpr]) and (val = reduce(compiler)).kind_of? ::Numeric
          @lexpr = nil
          @op = nil
          @rexpr = val
        end

        self
      end
    end
  end
end
end
