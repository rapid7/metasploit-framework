#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class CdecompListingWidget < DrawableWidget
  attr_accessor :dasm, :curaddr, :tabwidth

  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    @view_x = @view_y = 0	# coord of corner of view in characters
    @cwidth = @cheight = 1	# widget size in chars
    @line_text = []
    @line_text_col = []	# each line is [[:col, 'text'], [:col, 'text']]
    @curaddr = nil
    @tabwidth = 8

    @default_color_association = { :text => :black, :keyword => :blue, :caret => :black,
        :background => :white, :hl_word => :palered, :localvar => :darkred,
        :globalvar => :darkgreen, :intrinsic => :darkyellow }
  end

  def curfunc
    @dasm.c_parser and (@dasm.c_parser.toplevel.symbol[@curaddr] or @dasm.c_parser.toplevel.struct[@curaddr])
  end

  def click(x, y)
    @caret_x = (x-1).to_i / @font_width + @view_x
    @caret_y = y.to_i / @font_height + @view_y
    update_caret
  end

  def rightclick(x, y)
    click(x, y)
    if @dasm.c_parser and @dasm.c_parser.toplevel.symbol[@hl_word]
      @parent_widget.clone_window(@hl_word, :decompile)
    elsif @hl_word
      @parent_widget.clone_window(@hl_word)
    end
  end

  def doubleclick(x, y)
    click(x, y)
    @parent_widget.focus_addr(@hl_word)
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up
      if @caret_y > 0
        @view_y -= 4
        @caret_y -= 4
        @caret_y = 0 if @caret_y < 0
      end
    when :down
      if @caret_y < @line_text.length - 1
        @view_y += 4
        @caret_y += 4
        redraw
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

    # renders a string at current cursor position with a color
    # must not include newline
    render = lambda { |str, color|
      # function ends when we write under the bottom of the listing
      if @hl_word
        stmp = str
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
      draw_string_color(color, x, y, str)
      x += str.length * @font_width
    }

    @line_text_col[@view_y, @cheight + 1].each { |l|
      cx = 0
      l.each { |c, t|
        cx += t.length
        if cx-t.length > @view_x + @cwidth + 1
        elsif cx < @view_x
        else
          t = t[(@view_x - cx + t.length)..-1] if cx-t.length < @view_x
          render[t, c]
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
    when ?n	# rename local/global variable
      f = curfunc.initializer if curfunc and curfunc.initializer.kind_of? C::Block
      n = @hl_word
      if (f and f.symbol[n]) or @dasm.c_parser.toplevel.symbol[n]
        @parent_widget.inputbox("new name for #{n}", :text => n) { |v|
          if v !~ /^[a-z_$][a-z_0-9$]*$/i
            @parent_widget.messagebox("invalid name #{v.inspect} !")
            next
          end
          if f and f.symbol[n]
            # TODO add/update comment to the asm instrs
            s = f.symbol[v] = f.symbol.delete(n)
            s.name = v
            f.decompdata[:stackoff_name][s.stackoff] = v if s.stackoff
          elsif @dasm.c_parser.toplevel.symbol[n]
            @dasm.rename_label(n, v)
            @curaddr = v if @curaddr == n                   
          end
          gui_update
        }
      end
    when ?r # redecompile
      @parent_widget.decompile(@curaddr)
    when ?t	# change variable type (you'll want to redecompile after that)
      f = curfunc.initializer if curfunc.kind_of? C::Variable and curfunc.initializer.kind_of? C::Block
      n = @hl_word
      cp = @dasm.c_parser
      if (f and s = f.symbol[n]) or s = cp.toplevel.symbol[n] or s = cp.toplevel.symbol[@curaddr]
        s_ = s.dup
        s_.initializer = nil if s.kind_of? C::Variable	# for static var, avoid dumping the initializer in the textbox
        s_.attributes &= C::Attributes::DECLSPECS if s_.attributes
        @parent_widget.inputbox("new type for #{s.name}", :text => s_.dump_def(cp.toplevel)[0].join(' ')) { |t|
          if t == ''
            if s.type.kind_of? C::Function and s.initializer and s.initializer.decompdata
              s.initializer.decompdata[:stackoff_type].clear
              s.initializer.decompdata.delete :return_type
            elsif s.kind_of? C::Variable and s.stackoff
              f.decompdata[:stackoff_type].delete s.stackoff
            end
            next
          end
          begin
            cp.lexer.feed(t)
            raise 'bad type' if not v = C::Variable.parse_type(cp, cp.toplevel, true)
            v.parse_declarator(cp, cp.toplevel)
            if s.type.kind_of? C::Function and s.initializer and s.initializer.decompdata
              # updated type of a decompiled func: update stack
              vt = v.type.untypedef
              vt = vt.type.untypedef if vt.kind_of? C::Pointer
              raise 'function forever !' if not vt.kind_of? C::Function
              # TODO _declspec
              ao = 1
              vt.args.to_a.each { |a|
                next if a.has_attribute_var('register')
                ao = (ao + [cp.sizeof(a), cp.typesize[:ptr]].max - 1) / cp.typesize[:ptr] * cp.typesize[:ptr]
                s.initializer.decompdata[:stackoff_name][ao] = a.name if a.name
                s.initializer.decompdata[:stackoff_type][ao] = a.type
                ao += cp.sizeof(a)
              }
              s.initializer.decompdata[:return_type] = vt.type
              s.type = v.type
            else
              f.decompdata[:stackoff_type][s.stackoff] = v.type if f and s.kind_of? C::Variable and s.stackoff
              s.type = v.type
            end
            gui_update
          rescue Object
            @parent_widget.messagebox([$!.message, $!.backtrace].join("\n"), "error")
          end
          cp.readtok until cp.eos?
        }
      end
    else return false
    end
    true
  end

  def get_cursor_pos
    [@curaddr, @caret_x, @caret_y, @view_y]
  end

  def set_cursor_pos(p)
    focus_addr p[0]
    @caret_x, @caret_y, @view_y = p[1, 3]
    update_caret
  end

  # hint that the caret moved
  # redraws the caret, change the hilighted word, redraw if needed
  def update_caret
    redraw if @caret_x < @view_x or @caret_x >= @view_x + @cwidth or @caret_y < @view_y or @caret_y >= @view_y + @cheight

    invalidate_caret(@oldcaret_x-@view_x, @oldcaret_y-@view_y)
    invalidate_caret(@caret_x-@view_x, @caret_y-@view_y)
    @oldcaret_x, @oldcaret_y = @caret_x, @caret_y

    redraw if update_hl_word(@line_text[@caret_y], @caret_x)
  end

  # focus on addr
  # returns true on success (address exists & decompiled)
  def focus_addr(addr)
    if @dasm.c_parser and (@dasm.c_parser.toplevel.symbol[addr] or @dasm.c_parser.toplevel.struct[addr])
      @curaddr = addr
      @caret_x = @caret_y = 0
      gui_update
      return true
    end

    return if not addr = @parent_widget.normalize(addr)

    # scan up to func start/entrypoint
    todo = [addr]
    done = []
    ep = @dasm.entrypoints.to_a.inject({}) { |h, e| h.update @dasm.normalize(e) => true }
    while addr = todo.pop
      next if not di = @dasm.di_at(addr)
      addr = di.block.address
      next if done.include?(addr) or not @dasm.di_at(addr)
      done << addr
      break if @dasm.function[addr] or ep[addr]
      empty = true
      @dasm.decoded[addr].block.each_from_samefunc(@dasm) { |na| empty = false ; todo << na }
      break if empty
    end
    @dasm.auto_label_at(addr, 'loc') if @dasm.get_section_at(addr) and not @dasm.get_label_at(addr)
    return if not l = @dasm.get_label_at(addr)
    @curaddr = l
    @caret_x = @caret_y = 0
    gui_update
    true
  end

  # returns the address of the data under the cursor
  def current_address
    @curaddr
  end

  def update_line_text
    @line_text = curfunc.dump_def(@dasm.c_parser.toplevel)[0].map { |l| l.gsub("\t", ' '*@tabwidth) }
    @line_text_col = []

    if f = curfunc and f.kind_of? C::Variable and f.initializer.kind_of? C::Block
      keyword_re = /\b(#{C::Keyword.keys.join('|')})\b/
      intrinsic_re = /\b(intrinsic_\w+)\b/
      lv = f.initializer.symbol.keys
      lv << '00' if lv.empty?
      localvar_re = /\b(#{lv.join('|')})\b/
      globalvar_re = /\b(#{f.initializer.outer.symbol.keys.join('|')})\b/
    end

    @line_text.each { |l|
      lc = []
      if f
        while l and l.length > 0
          if (i_k = (l =~ keyword_re)) == 0
            m = $1.length
            col = :keyword
          elsif (i_i = (l =~ intrinsic_re)) == 0
            m = $1.length
            col = :intrinsic
          elsif (i_l = (l =~ localvar_re)) == 0
            m = $1.length
            col = :localvar
          elsif (i_g = (l =~ globalvar_re)) == 0
            m = $1.length
            col = :globalvar
          else
            m = ([i_k, i_i, i_l, i_g, l.length] - [nil, false]).min
            col = :text
          end
          lc << [col, l[0, m]]
          l = l[m..-1]
        end
      else
        lc << [:text, l]
      end
      @line_text_col << lc
    }
  end

  def gui_update
    if not curfunc and not @decompiling ||= false
      @line_text = ['please wait']
      @line_text_col = [[[:text, 'please wait']]]
      redraw
      @decompiling = true
      @dasm.decompile_func(@curaddr)
      @decompiling = false
    end
    if curfunc
      update_line_text
      update_caret
    end
    redraw
  end
end
end
end
