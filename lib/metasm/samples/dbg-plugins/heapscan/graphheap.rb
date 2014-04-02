#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module ::Metasm
module Gui
class GraphHeapWidget < GraphViewWidget
  attr_accessor :heap, :addr_struct, :snapped
  # addr_struct = 0x234 => AllocCStruct

  def set_color_arrow(b1, b2)
    if b1 == @caret_box or b2 == @caret_box
      draw_color :arrow_hl
    else
      draw_color :arrow_cond
    end
  end

  def setup_contextmenu(b, m)
    addsubmenu(m, '_follow pointer') {
      next if not lm = b[:line_member][@caret_y]
      addr = b[:line_struct][@caret_y][lm]
      next if not @heap.chunks[addr]
      if lm.kind_of?(::Integer)
        t = b[:line_struct][@caret_y].struct.type
      else
        t = lm.type
      end
      if t.pointer? and t.pointed.untypedef.kind_of? C::Union
        @heap.chunk_struct[addr] ||= t.pointed.untypedef
      end
      st = @heap.chunk_struct[addr] || create_struct(addr)
      ed = @dasm.get_edata_at(addr)
      @addr_struct[addr] = @heap.cp.decode_c_struct(st.name, ed.data, ed.ptr)
      gui_update
    }
    addsubmenu(m, '_hide box') {
      @selected_boxes.each { |sb|
        @addr_struct.delete sb.id if @addr_struct.length > 1
      }
      @curcontext.root_addrs = struct_find_roots(@addr_struct.keys.first)
      gui_update
    }
    super(b, m)
  end

  def keypress(k)
    case k
    when ?u
      # update display (refresh struct member values)
      @parent_widget.parent_widget.console.commands['refresh'][]
      gui_update
    when ?t
      # change struct field type
      if @selected_boxes.length > 1
        # mass-retype chunks
        st = @addr_struct[@selected_boxes[0].id].struct
        inputbox("replacement struct for selected chunks", :text => st.name) { |n|
          next if not nst = @heap.cp.toplevel.struct[n]
          @selected_boxes.each { |sb|
            as = @addr_struct[sb.id]
            @heap.chunk_struct[sb.id] = nst
            @addr_struct[sb.id] = @heap.cp.decode_c_struct(n, as.str, as.stroff)
          }
          gui_update
        }
      elsif b = @caret_box
        if @caret_y == 0
          as = @addr_struct[b.id]
          st = as.struct
          inputbox("replacement struct for #{st.name}", :text => st.name) { |n|
            next if not nst = @heap.cp.toplevel.struct[n]
            @heap.chunk_struct[b.id] = nst
            @addr_struct[b.id] = @heap.cp.decode_c_struct(n, as.str, as.stroff)
            gui_update
          }
        elsif m = b[:line_member][@caret_y]
          if m.kind_of?(Integer)
            # XXX Array, need to find the outer struct
            mn = b[:line_text_col][@caret_y].map { |l, c| l }.join[/(\S*)\[/, 1]
            ar = b[:line_struct][@caret_y]
            st = b[:line_struct][0...@caret_y].reverse.compact.find { |st_| st_.struct.kind_of?(C::Struct) and st_[mn].struct == ar.struct }
            raise '?' if not st
            st = st.struct
            m = st.fldlist[mn]
          else
            st = b[:line_struct][@caret_y].struct
          end
          inputbox("new type for #{m.name}", :text => m.dump_def(@heap.cp.toplevel)[0].join(' ')) { |nn|
            nil while @heap.cp.readtok
            @heap.cp.lexer.feed nn
            if not v = C::Variable.parse_type(@heap.cp, @heap.cp.toplevel, true)
              nil while @heap.cp.readtok
              raise 'bad type'
            end
            v.parse_declarator(@heap.cp, @heap.cp.toplevel)
            nt = v.type
            nsz = @heap.cp.sizeof(nt)
            osz = @heap.cp.sizeof(m)
            if nsz > osz and st.kind_of?(C::Struct)
              idx = st.members.index(m)
              # eat next members
              while nsz > osz
                break if idx+1 >= st.members.length
                sz = @heap.cp.sizeof(st.members.delete_at(idx+1))
                osz += sz
              end
            end
            if nsz < osz and st.kind_of?(C::Struct)
              idx = st.members.index(m)
              pos = st.offsetof(@heap.cp, m)
              # fill gap with bytes
              idx += 1
              while nsz < osz
                st.members[idx, 0] = [C::Variable.new(('unk_%x' % (pos+nsz)), C::BaseType.new(:__int8, :unsigned))]
                idx += 1
                nsz += 1
              end
            end
            m.type = nt
            st.update_member_cache(@heap.cp)
            gui_update
          }

        end
      end
    when ?n
      # rename struct field
      if b = @caret_box
        if @caret_y == 0
          st = @addr_struct[b.id].struct
          inputbox("new name for #{st.name}", :text => st.name) { |nn|
            raise "struct #{nn} already exists (try 't')" if @heap.cp.toplevel.struct[nn]
            @heap.cp.toplevel.struct[nn] = @heap.cp.toplevel.struct.delete(st.name)
            st.name = nn
            gui_update
          }
        elsif m = b[:line_member][@caret_y]
          if m.kind_of?(Integer)
            mn = b[:line_text_col][@caret_y].map { |l, c| l }.join[/(\S*)\[/, 1]
            ar = b[:line_struct][@caret_y]
            st = b[:line_struct][0...@caret_y].reverse.compact.find { |st_| st_.struct.kind_of?(C::Struct) and st_[mn].struct == ar.struct }
            raise '?' if not st
            st = st.struct
            m = st.fldlist[mn]
          else
            st = b[:line_struct][@caret_y].struct
          end
          inputbox("new name for #{m.name}", :text => m.name) { |nn|
            m.name = nn
            st.update_member_cache(@heap.cp)
            gui_update
          }
        end
      end
    when ?e
      # edit struct field value under the cursor
      if b = @caret_box
        # TODO b[:struct][line], b.[:member][line] (int for Arrays)
        st = b[:line_struct][@caret_y]
        mb = b[:line_member][@caret_y]
        if st and mb
          if mb.kind_of?(C::Variable) and mb.type.kind_of?(C::Array) and mb.type.type.kind_of?(C::BaseType) and mb.type.type.name == :char
            defval = st[mb].to_array.pack('C*').gsub(/\0*$/, '').gsub(/[^\x20-\x7e]/, '.')
            string = true
          else
            defval = st[mb]
            string = false
          end
          inputbox("new value for #{mb.respond_to?(:name) ? mb.name : mb}", :text => defval.to_s) { |nn|
            if string
              am = st[mb]
              (nn.unpack('C*') + [0]).each_with_index { |b_, i| am[i] = b_ }
            else
              st[mb] = Expression.parse_string(nn).reduce
            end
            gui_update
          }
        end
      end
    when ?x
      # show heap xrefs to the hilighted chunk
      if b = @caret_box
        list = [['address', 'size']]
        @heap.xrchunksfrom[b.id].to_a.each { |a|
          list << [Expression[a], Expression[@heap.chunks[a]]]
        }
        if list.length == 1
          messagebox "no xref to #{Expression[b.id]}"
        else
          listwindow("heap xrefs to #{Expression[b.id]}", list) { |i| @parent_widget.focus_addr(i[0], nil, true) }
        end
      end
    when ?I
      # insert new field in struct
      if b = @caret_box
        if m = b[:line_member][@caret_y]
          if m.kind_of?(Integer)
            # XXX Array, need to find the outer struct
            mn = b[:line_text_col][@caret_y].map { |l, c| l }.join[/(\S*)\[/, 1]
            ar = b[:line_struct][@caret_y]
            st = b[:line_struct][0...@caret_y].reverse.compact.find { |st_| st_.struct.kind_of?(C::Struct) and st_[mn].struct == ar.struct }
            raise '?' if not st
            st = st.struct
            m = st.fldlist[mn]
          else
            st = b[:line_struct][@caret_y].struct
          end
          inputbox("new type to insert before #{m.name}", :text => m.dump_def(@heap.cp.toplevel)[0].join(' ')) { |nn|
            nil while @heap.cp.readtok
            @heap.cp.lexer.feed nn
            if not v = C::Variable.parse_type(@heap.cp, @heap.cp.toplevel, true)
              nil while @heap.cp.readtok
              raise 'bad type'
            end
            v.parse_declarator(@heap.cp, @heap.cp.toplevel)
            nt = v.type
            idx = st.members.index(m)
            pos = st.offsetof(@heap.cp, m)
            name = oname = v.name || ('unk_%x_new' % pos)
            cntr = 0
            while st.members.find { |m_| m_.name == name }
              name = oname + "_#{cntr+=1}"
            end
            st.members[idx, 0] = [C::Variable.new(name, nt)]
            st.update_member_cache(@heap.cp)
            gui_update
          }

        end
      end
    when ?S
      # delete structure field
      if b = @caret_box
        if m = b[:line_member][@caret_y]
          if m.kind_of?(Integer)
            # XXX Array, need to find the outer struct
            mn = b[:line_text_col][@caret_y].map { |l, c| l }.join[/(\S*)\[/, 1]
            ar = b[:line_struct][@caret_y]
            st = b[:line_struct][0...@caret_y].reverse.compact.find { |st_| st_.struct.kind_of?(C::Struct) and st_[mn].struct == ar.struct }
            raise '?' if not st
            st = st.struct
            m = st.fldlist[mn]
          else
            st = b[:line_struct][@caret_y].struct
          end
          inputbox("delete #{m.name} ?") { |nn|
            idx = st.members.index(m)
            st.members.delete_at(idx)
            st.update_member_cache(@heap.cp)
            gui_update
          }

        end
      end
    when ?+
      # append blocks linked from the currently shown blocks to the display
      @addr_struct.keys.each { |ak|
        @heap.xrchunksto[ak].to_a.each { |nt|
          next if @addr_struct[nt]
          # TODO check if the pointer is a some_struct*
          st = @heap.chunk_struct[nt] || create_struct(nt)
          ed = @dasm.get_edata_at(nt)
          @addr_struct[nt] = @heap.cp.decode_c_struct(st.name, ed.data, ed.ptr)
        }
      }
      gui_update
    when ?-
      # remove graph leaves in an attempt to undo ?+
      unk = @addr_struct.keys.find_all { |ak|
        (@heap.xrchunksto[ak].to_a & @addr_struct.keys).empty?
      }
      unk.each { |ak| @addr_struct.delete ak if @addr_struct.length > 1 }
      gui_update
    else return super(k)
    end
    true
  end

  # create the graph objects in ctx
  def build_ctx(ctx)
    # create boxes
    todo = ctx.root_addrs.dup & @addr_struct.keys
    todo << @addr_struct.keys.first if todo.empty?
    done = []
    while a = todo.shift
      next if done.include? a
      done << a
      ctx.new_box a, :line_text_col => [], :line_address => [], :line_struct => [], :line_member => []
      todo.concat @heap.xrchunksto[a].to_a & @addr_struct.keys
    end

    # link boxes
    if (@heap.xrchunksto[ctx.box.first.id].to_a & @addr_struct.keys).length == ctx.box.length - 1
      ot = ctx.box[0].id
      ctx.box[1..-1].each { |b_|
        ctx.link_boxes(ot, b_.id)
      }
    else
      ctx.box.each { |b|
        @heap.xrchunksto[b.id].to_a.each { |t|
          ctx.link_boxes(b.id, t) if @addr_struct[t]
        }
      }
    end

    if snapped
      @datadiff = {}
    end

    # calc box dimensions/text
    ctx.box.each { |b|
      colstr = []
      curaddr = b.id
      curst = @addr_struct[b.id]
      curmb = nil
      margin = ''
      start_addr = curaddr
      if snapped
        ghosts = snapped[curaddr]
      end
      line = 0
      render = lambda { |str, col| colstr << [str, col] }
      nl = lambda {
        b[:line_address][line] = curaddr
        b[:line_text_col][line] = colstr
        b[:line_struct][line] = curst
        b[:line_member][line] = curmb
        colstr = []
        line += 1
      }
      render_val = lambda { |v|
        if v.kind_of?(::Integer)
          if v > 0x100
            render['0x%X' % v, :text]
          elsif v < -0x100
            render['-0x%X' % -v, :text]
          else
            render[v.to_s, :text]
          end
        elsif not v
          render['NULL', :text]
        else
          render[v.to_s, :text]
        end
      }
      render_st = nil
      render_st_ar = lambda { |ast, m|
        elemt = m.type.untypedef.type.untypedef
        if elemt.kind_of?(C::BaseType) and elemt.name == :char
          render[margin, :text]
          render["#{m.type.type.to_s[1...-1]} #{m.name}[#{m.type.length}] = #{ast[m].to_array.pack('C*').sub(/\0.*$/m, '').inspect}", :text]
          nl[]
          curaddr += ast.cp.sizeof(m)
        else
          t = m.type.type.to_s[1...-1]
          tsz = ast.cp.sizeof(m.type.type)
          fust = curst
          fumb = curmb
          curst = ast[m]
          ast[m].to_array.each_with_index { |v, i|
            curmb = i
            render[margin, :text]
            if elemt.kind_of?(C::Union)
              if m.type.untypedef.type.kind_of?(C::Union)
                render[elemt.kind_of?(C::Struct) ? 'struct ' : 'union ', :text]
                render["#{elemt.name} ", :text] if elemt.name
              else # typedef
                render["#{elemt.to_s[1...-1]} ", :text]
              end
              render_st[v]
              render[" #{m.name}[#{i}]", :text]
            else
              render["#{t} #{m.name}[#{i}] = ", :text]
              render_val[v]
              @datadiff[curaddr] = true if ghosts and ghosts.all? { |g| g[curaddr-start_addr, tsz] == ghosts[0][curaddr-start_addr, tsz] } and ghosts[0][curaddr-start_addr, tsz] != ast.str[curaddr, tsz].to_str
            end
            render[';', :text]
            nl[]
            curaddr += tsz
          }
          curst = fust
          curmb = fumb
        end
      }
      render_st = lambda { |ast|
        st_addr = curaddr
        oldst = curst
        oldmb = curmb
        oldmargin = margin
        render['{', :text]
        nl[]
        margin += '    '
        curst = ast
        ast.struct.members.each { |m|
          curmb = m
          curaddr = st_addr + ast.struct.offsetof(@heap.cp, m)

          if bo = ast.struct.bitoffsetof(@heap.cp, m)
            # float curaddr to make ghost hilight work on bitfields
            curaddr += (1+bo[0])/1000.0
          end

          if m.type.untypedef.kind_of?(C::Array)
            render_st_ar[ast, m]
          elsif m.type.untypedef.kind_of?(C::Union)
            render[margin, :text]
            if m.type.kind_of?(C::Union)
              render[m.type.kind_of?(C::Struct) ? 'struct ' : 'union ', :text]
              render["#{m.type.name} ", :text] if m.type.name
            else # typedef
              render["#{m.type.to_s[1...-1]} ", :text]
            end
            oca = curaddr
            render_st[ast[m]]
            nca = curaddr
            curaddr = oca
            render[" #{m.name if m.name};", :text]
            nl[]
            curaddr = nca
          else
            render[margin, :text]
            render["#{m.type.to_s[1...-1]} ", :text]
            render["#{m.name} = ", :text]
            render_val[ast[m]]
            tsz = ast.cp.sizeof(m)
            # TODO bit-level multighosting
            if ghosts and ghosts.all? { |g| g[curaddr.to_i-start_addr, tsz] == ghosts[0][curaddr.to_i-start_addr, tsz] } and ghosts[0][curaddr.to_i-start_addr, tsz] != ast.str[curaddr.to_i, tsz].to_str
              if bo
                ft = C::BaseType.new((bo[0] + bo[1] > 32) ? :__int64 : :__int32)
                v1 = @heap.cp.decode_c_value(ghosts[0][curaddr.to_i-start_addr, tsz], ft, 0)
                v2 = @heap.cp.decode_c_value(ast.str[curaddr.to_i, tsz], ft, 0)
                @datadiff[curaddr] = true if (v1 >> bo[0]) & ((1 << bo[1])-1) != (v2 >> bo[0]) & ((1 << bo[1])-1)
              else
                @datadiff[curaddr] = true
              end
            end
            render[';', :text]

            if m.type.kind_of?(C::Pointer) and m.type.type.kind_of?(C::BaseType) and m.type.type.name == :char
              if s = @dasm.decode_strz(ast[m], 32)
                render["    // #{s.inspect}", :comment]
              end
            end
            nl[]
            curaddr += tsz
            curaddr = curaddr.to_i if bo
          end
        }
        margin = oldmargin
        curst = oldst
        curmb = oldmb
        render[margin, :text]
        render['}', :text]
      }
      ast = @addr_struct[curaddr]
      render["struct #{ast.struct.name} *#{'0x%X' % curaddr} = ", :text]
      render_st[ast]
      render[';', :text]
      nl[]

      b.w = b[:line_text_col].map { |strc| strc.map { |s, c| s }.join.length }.max.to_i * @font_width + 2
      b.w += 1 if b.w % 2 == 0
      b.h = line * @font_height
    }
  end

  def struct_find_roots(addr)
    addr = @addr_struct.keys.find { |a| addr >= a and addr < a+@addr_struct[a].sizeof } if not @addr_struct[addr]

    todo = [addr]
    done = []
    roots = []
    default_root = nil
    while a = todo.shift
      if done.include?(a) # cycle
        default_root ||= a
        next
      end
      done << a
      newf = @heap.xrchunksfrom[a].to_a & @addr_struct.keys
      if newf.empty?
        roots << a
      else
        todo.concat newf
      end
    end
    roots << default_root if roots.empty? and default_root

    roots
  end

  def focus_addr(addr, fu=nil)
    return if @parent_widget and not addr = @parent_widget.normalize(addr)

    # move window / change curcontext
    if b = @curcontext.box.find { |b_| b_[:line_address].index(addr) }
      @caret_box, @caret_x, @caret_y = b, 0, b[:line_address].rindex(addr)
      @curcontext.view_x += (width/2 / @zoom - width/2)
      @curcontext.view_y += (height/2 / @zoom - height/2)
      @zoom = 1.0

      focus_xy(b.x, b.y + @caret_y*@font_height)
      update_caret
    elsif addr_struct and (@addr_struct[addr] or @addr_struct.find { |a, s| addr >= a and addr < a+s.sizeof })
      @curcontext = Graph.new 'testic'
      @curcontext.root_addrs = struct_find_roots(addr)
      @want_focus_addr = addr
      gui_update
    elsif @heap.chunks[addr]
      @want_focus_addr = addr
      do_focus_addr(addr)
    else
      return
    end
    true
  end

  def do_focus_addr(addr)
    st = @heap.chunk_struct[addr] || create_struct(addr)

    ed = @dasm.get_edata_at(addr)
    @addr_struct = { addr => @heap.cp.decode_c_struct(st.name, ed.data, ed.ptr) }
    gui_update
  end

  # create the struct chunk_<addr>, register it in @heap.chunk_struct
  def create_struct(addr)
    raise "no chunk here" if not @heap.chunks[addr]

    ptsz = @dasm.cpu.size/8

    # check if this is a c++ object with RTTI info
    vptr = @dasm.decode_dword(addr)
    rtti = @dasm.decode_dword(vptr-ptsz)
    case OS.shortname
    when 'winos'
      typeinfo = @dasm.decode_dword(rtti+3*ptsz) if rtti
      if typeinfo and s = @dasm.decode_strz(typeinfo+3*ptsz)
        rtti_name = s[/^(.*)@@$/, 1]	# remove trailing @@
      end
    when 'linos'
      typeinfo = @dasm.decode_dword(rtti+ptsz) if rtti
      if typeinfo and s = @dasm.decode_strz(typeinfo)
        rtti_name = s[/^[0-9]+(.*)$/, 1]	# remove leading number
      end
    end

    if rtti_name and st = @heap.cp.toplevel.struct[rtti_name]
      return @heap.chunk_struct[addr] = st
    end

    st = C::Struct.new
    st.name = rtti_name || "chunk_#{'%x' % addr}"
    st.members = []
    li = 0
    (@heap.chunks[addr] / ptsz).times { |i|
      n = 'unk_%x' % (ptsz*i)
      v = @dasm.decode_dword(addr+ptsz*i)
      if i == 0 and rtti_name
        t = C::Pointer.new(C::Pointer.new(C::BaseType.new(:void)))
        n = 'vtable'
      elsif @heap.chunks[v]
        t = C::Pointer.new(C::BaseType.new(:void))
      else
        t = C::BaseType.new("__int#{ptsz*8}".to_sym, :unsigned)
      end
      st.members << C::Variable.new(n, t)
      li = i+1
    }
    (@heap.chunks[addr] % ptsz).times { |i|
      n = 'unk_%x' % (ptsz*li+i)
      t = C::BaseType.new(:char, :unsigned)
      st.members << C::Variable.new(n, t)
    }
    @heap.cp.toplevel.struct[st.name] = st
    @heap.chunk_struct[addr] = st
  end

  def snap
    if not snapped
      @datadiff = {}
      ocb = @parent_widget.bg_color_callback
      @parent_widget.bg_color_callback = lambda { |a|
        if @datadiff[a]
          'f88'
        elsif ocb
          ocb[a]
        end
      }
    end
    @snapped = {}
    @addr_struct.each { |a, ast|
      @snapped[a] = [ast.str[ast.stroff, ast.sizeof].to_str]
    }
  end

  def snap_add
    return snap if not snapped
    @addr_struct.each { |a, ast|
      (@snapped[a] ||= []) << ast.str[ast.stroff, ast.sizeof].to_str
    }
  end

  def get_cursor_pos
    [super, addr_struct]
  end

  def set_cursor_pos(p)
    s, @addr_struct = p
    super(s)
  end
end
end
end
