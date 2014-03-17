#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class CStructWidget < DrawableWidget
  attr_accessor :dasm, :view_x, :view_y

  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    @line_text_col = []	# each line is [[:col, 'text'], [:col, 'text']]
    @line_text = []
    @line_dereference = []	# linenr => [addr, struct] (args to focus_addr)
    @curaddr = nil
    @curstruct = nil
    @tabwidth = 8
    @view_x = @view_y = 0
    @caret_x = @caret_y = 0
    @cwidth = @cheight = 1	# widget size in chars
    @structdepth = 2

    @default_color_association = { :text => :black, :keyword => :blue, :caret => :black,
        :background => :white, :hl_word => :palered, :comment => :darkblue }
  end

  def click(x, y)
    @caret_x = (x-1).to_i / @font_width + @view_x
    @caret_y = y.to_i / @font_height + @view_y
    update_caret
  end

  def rightclick(x, y)
    click(x, y)
    @parent_widget.clone_window(@hl_word) if @hl_word
  end

  def doubleclick(x, y)
    click(x, y)
    keypress(:enter)
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up
      if @caret_y > 0
        @view_y -= 4
        @view_y = 0 if @view_y < 0
        @caret_y -= 4
        @caret_y = 0 if @caret_y < 0
      end
    when :down
      if @caret_y < @line_text.length - 1
        @view_y += 4
        @caret_y += 4
      end
    end
    redraw
  end

  def paint
    @cwidth = width/@font_width
    @cheight = height/@font_height

    # adjust viewport to cursor
    sz_x = @line_text.map { |l| l.length }.max.to_i + 1
    sz_y = @line_text.length.to_i + 1
    @view_x = @caret_x - @cwidth + 1 if @caret_x > @view_x + @cwidth - 1
    @view_x = @caret_x if @caret_x < @view_x
    @view_x = sz_x - @cwidth - 1 if @view_x >= sz_x - @cwidth
    @view_x = 0 if @view_x < 0

    @view_y = @caret_y - @cheight + 1 if @caret_y > @view_y + @cheight - 1
    @view_y = @caret_y if @caret_y < @view_y
    @view_y = sz_y - @cheight - 1 if @view_y >= sz_y - @cheight
    @view_y = 0 if @view_y < 0

    # current cursor position
    x = 1
    y = 0

    @line_text_col[@view_y, @cheight + 1].each { |l|
      cx = 0
      l.each { |c, t|
        cx += t.length
        if cx-t.length > @view_x + @cwidth + 1
        elsif cx < @view_x
        else
          t = t[(@view_x - cx + t.length)..-1] if cx-t.length < @view_x
          if @hl_word
            stmp = t
            pre_x = 0
            while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
              s1, s2 = $1, $2
              pre_x += s1.length*@font_width
              hl_w = s2.length*@font_width
              draw_rectangle_color(:hl_word, x+pre_x, y, hl_w, @font_height)
              pre_x += hl_w
              stmp = stmp[s1.length+s2.length..-1]
            end
          end
          draw_string_color(c, x, y, t)
          x += t.length * @font_width
        end
      }
      x = 1
      y += @font_height
    }

    if focus?
      # draw caret
      cx = (@caret_x-@view_x)*@font_width+1
      cy = (@caret_y-@view_y)*@font_height
      draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
    end
  
    @oldcaret_x, @oldcaret_y = @caret_x, @caret_y
  end

  def keypress(key)
    case key
    when :left
      if @caret_x >= 1
        @caret_x -= 1
        update_caret
      end
    when :up
      if @caret_y > 0
        @caret_y -= 1
        update_caret
      end
    when :right
      if @caret_x < @line_text[@caret_y].to_s.length
        @caret_x += 1
        update_caret
      end
    when :down
      if @caret_y < @line_text.length
        @caret_y += 1
        update_caret
      end
    when :home
      @caret_x = @line_text[@caret_y].to_s[/^\s*/].length
      update_caret
    when :end
      @caret_x = @line_text[@caret_y].to_s.length
      update_caret
    when :pgup
      @caret_y -= @cheight/2
      @caret_y = 0 if @caret_y < 0
      update_caret
    when :pgdown
      @caret_y += @cheight/2
      @caret_y = @line_text.length if @caret_y > @line_text.length
      update_caret
    when :enter
      if l = @line_dereference[@caret_y]
        if @parent_widget
          @parent_widget.focus_addr(l[0], :cstruct, false, l[1])
        else
          focus_addr(l[0], l[1])
        end
      end
    when ?+
      @structdepth += 1
      gui_update
    when ?-
      @structdepth -= 1
      gui_update
    when ?/
      @structdepth = 1
      gui_update
    when ?*
      @structdepth =  50
      gui_update
    when ?l
      liststructs
    when ?t
      inputbox('new struct name to use', :text => (@curstruct.name rescue '')) { |n|
        lst = @dasm.c_parser.toplevel.struct.keys.grep(String)
        if fn = lst.find { |ln| ln == n } || lst.find { |ln| ln.downcase == n.downcase }
          focus_addr(@curaddr, @dasm.c_parser.toplevel.struct[fn])
        else
          lst = @dasm.c_parser.toplevel.symbol.keys.grep(String).find_all { |ln|
            s = @dasm.c_parser.toplevel.symbol[ln]
            s.kind_of?(C::TypeDef) and s.untypedef.kind_of?(C::Union)
          }
          if fn = lst.find { |ln| ln == n } || lst.find { |ln| ln.downcase == n.downcase }
            focus_addr(@curaddr, @dasm.c_parser.toplevel.symbol[fn].untypedef)
          else
            liststructs(n)
          end
        end
      }
    else return false
    end
    true
  end

  def liststructs(partname=nil)
    tl = @dasm.c_parser.toplevel
    list = [['name', 'size']]
    list += tl.struct.keys.grep(String).sort.map { |stn|
      next if partname and stn !~ /#{partname}/i
      st = tl.struct[stn]
      [stn, @dasm.c_parser.sizeof(st)] if st.members
    }.compact
    list += tl.symbol.keys.grep(String).sort.map { |stn|
      next if partname and stn !~ /#{partname}/i
      st = tl.symbol[stn]
      next unless st.kind_of?(C::TypeDef) and st.untypedef.kind_of?(C::Union)
      [stn, @dasm.c_parser.sizeof(st)] if st.untypedef.members
    }.compact

    if partname and list.length == 2
      focus_addr(@curaddr, tl.struct[list[1][0]] || tl.symbol[list[1][0]].untypedef)
      return
    end

    listwindow('structs', list) { |stn|
      focus_addr(@curaddr, tl.struct[stn[0]] || tl.symbol[stn[0]].untypedef)
    }
  end

  def get_cursor_pos
    [@curaddr, @curstruct, @caret_x, @caret_y, @view_y]
  end

  def set_cursor_pos(p)
    focus_addr p[0], p[1]
    @caret_x, @caret_y, @view_y = p[2, 3]
    update_caret
  end

  # hint that the caret moved
  # redraws the caret, change the hilighted word, redraw if needed
  def update_caret
    if @caret_x < @view_x or @caret_x >= @view_x + @cwidth or @caret_y < @view_y or @caret_y >= @view_y + @cheight
      redraw
    elsif update_hl_word(@line_text[@caret_y], @caret_x)
      redraw
    else
      invalidate_caret(@oldcaret_x-@view_x, @oldcaret_y-@view_y)
      invalidate_caret(@caret_x-@view_x, @caret_y-@view_y)
    end
    @oldcaret_x, @oldcaret_y = @caret_x, @caret_y
  end

  # focus on addr
  # returns true on success
  def focus_addr(addr, struct=@curstruct)
    return if @parent_widget and not addr = @parent_widget.normalize(addr)
    @curaddr = addr
    @curstruct = struct
    @caret_x = @caret_y = 0
    gui_update
    true
  end

  # returns the address of the data under the cursor
  def current_address
    @curaddr
  end

  def render_struct(obj=nil, off=nil, maxdepth=@structdepth)
    render = lambda { |str, col|
      if @line_text_col.last[0] == col
        @line_text_col.last[1] << str
      else
        @line_text_col.last << [col, str]
      end
    }
    indent = ' ' * @tabwidth
    nl = lambda {
      @line_text_col << []
      render[indent * [@structdepth - maxdepth, 0].max, :text]
    }
    
    if not obj
      @line_text_col = [[]]
      @line_dereference = []

      struct = @curstruct
      if str = @dasm.get_section_at(@curaddr)
        obj = @dasm.c_parser.decode_c_struct(struct, str[0].read(@dasm.c_parser.sizeof(struct)))
      else
        render["/* unmapped area #{Expression[@curaddr]} */", :text]
        return
      end
    else
      struct = obj.struct
    end

    if maxdepth <= 0
      render['{ /* type "+" to expand */ }', :text]
      return
    end

    # from AllocCStruct#to_s
    if struct.kind_of?(C::Array)
      render["#{struct.type} ar_#{Expression[@curaddr]}[#{struct.length}] = ", :text] if not off
      mlist = (0...struct.length)
      el = @dasm.c_parser.sizeof(struct.type)
      fldoff = mlist.inject({}) { |h, i| h.update i => i*el }
    elsif struct.kind_of?(C::Struct)
      render["struct #{struct.name || '_'} st_#{Expression[@curaddr]} = ", :text] if not off
      fldoff = struct.fldoffset
      fbo = struct.fldbitoffset || {}
    else
      render["union #{struct.name || '_'} un_#{Expression[@curaddr]} = ", :text] if not off
    end
    mlist ||= struct.members
    render['{', :text]
    mlist.each { |k|
      if k.kind_of? C::Variable
        ct = k.type
        curoff = off.to_i + (fldoff && k.name ? fldoff[k.name].to_i : struct.offsetof(@dasm.c_parser, k))
        val = obj[k]
      else
        ct = struct.type
        curoff = off.to_i + fldoff[k].to_i
        val = obj[k]
      end
      nl[]
      render[indent, :text]
      render[k.kind_of?(Integer) ? "[#{k}]" : ".#{k.name || '?'}", :text]
      render[' = ', :text]
      if val.kind_of?(Integer)
        if ct.pointer? and ct.pointed.untypedef.kind_of?(C::Union)
          @line_dereference[@line_text_col.length-1] = [val, ct.pointed.untypedef]
        end
        if val >= 0x100
          val = '0x%X' % val
        elsif val <= -0x100
          val = '-0x%X' % -val
        else
          val = val.to_s
        end
      elsif val.kind_of?(C::AllocCStruct)
        render_struct(val, curoff, maxdepth-1)
        next
      elsif not val
        val = 'NULL' # pointer with NULL value
      else
        raise "unknown value #{val.inspect}"
      end
      render[val, :text]
      render[',', :text]
      render['   // +%x' % curoff, :comment]
    }
    nl[]
    render['}', :text]
    render[(off ? ',' : ';'), :text]
  end


  def gui_update
    if @curstruct
      render_struct
    else
      @line_text_col = [[[:text, '/* no struct selected (list with "l") */']]]
    end
    
    @line_text = @line_text_col.map { |l| l.map { |c, s| s }.join }
    update_caret
    redraw
  end
end
end
end
