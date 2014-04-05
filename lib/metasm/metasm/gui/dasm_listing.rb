#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class AsmListingWidget < DrawableWidget
  attr_accessor :dasm, :arrow_zone_w
  # nr of raw bytes to display next to each decoded instruction
  attr_accessor :raw_data_length

  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    @arrows = []	# array of [linefrom, lineto] (may be :up or :down for offscreen)
    @line_address = []
    @line_text = []
    @line_text_color = []
    @want_update_line_text = @want_update_caret = true
    @wantaddr = nil
    @arrow_zone_w = 40
    @raw_data_length = 0

    addrs = @dasm.sections.keys.grep(Integer)
    @minaddr = addrs.min.to_i
    @maxaddr = (addrs.max + @dasm.sections[addrs.max].length rescue (1 << @dasm.cpu.size))
    @startaddr = @dasm.prog_binding['entrypoint'] || @minaddr

    @default_color_association = ColorTheme.merge :raw_data => :black, :arrows_bg => :palegrey,
      :arrow_up => :darkblue, :arrow_dn => :darkyellow, :arrow_hl => :red
  end

  def resized(w, h)
    col = w/@font_width
    lin = h/@font_height
    @caret_x = col-1 if @caret_x >= col
    @caret_y = lin-1 if @caret_y >= lin and lin > 0
    gui_update
  end

  def adjust_startaddr(off=0, update = true)
    @startaddr += off
    @startaddr = @maxaddr - 1 if @startaddr.kind_of? Integer and @startaddr >= @maxaddr
    if off = (0..16).find { |off_| di = @dasm.decoded[@startaddr-off_] and di.respond_to? :bin_length and di.bin_length > off_ } and off != 0
      # align on @decoded boundary
      @startaddr -= off
    end
    @startaddr = @minaddr if @startaddr.kind_of? Integer and @startaddr < @minaddr
    gui_update if update
  end

  def click(x, y)
    set_caret_from_click(x - @arrow_zone_w, y)
    @caret_x = 0 if @caret_x < 0
  end

  def rightclick(x, y)
    click(x, y)
    cx = (x - @arrow_zone_w) / @font_width
    cy = y / @font_height
    if cx > 0
      m = new_menu
      cm = new_menu
      addsubmenu(cm, 'copy _word') { clipboard_copy(@hl_word) if @hl_word }
      addsubmenu(cm, 'copy _line') { clipboard_copy(@line_text[cy]) if @line_text[cy] }
      addsubmenu(cm, 'copy _all')  { clipboard_copy(@line_text.join("\r\n")) }	# XXX auto \r\n vs \n
      addsubmenu(m, '_clipboard', cm)
      addsubmenu(m, 'clone _window') { @parent_widget.clone_window(@hl_word, :listing) }
      if @parent_widget.respond_to?(:extend_contextmenu)
        @parent_widget.extend_contextmenu(self, m, @line_address[@caret_y])
      end
      popupmenu(m, x, y)
    end
  end

  def doubleclick(x, y)
    click(x, y)
    @parent_widget.focus_addr(@hl_word)
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up
      # TODO handle block start (multiline) / data aggregation (db 100h dup(?), strings..)
      @wantaddr = @line_address[@caret_y]
      adjust_startaddr(-1, false)
      adjust_startaddr(-1, false)
      adjust_startaddr(-1, false)
      adjust_startaddr(-1)
    when :down
      # scroll down 4 lines, or more if all the 4 1st lines have the same addr (eg block start)
      @wantaddr = @line_address[@caret_y]
      a = @line_address[4..-1].find { |v| v != @line_address[0] } if @line_address[4]
      @startaddr = a || (@startaddr + 4)
      adjust_startaddr
    end
  end

  # renders the disassembler from @startaddr
  def paint
    w_w = width
    w_h = height

    # arrow bg
    draw_rectangle_color(:arrows_bg, 0, 0, @arrow_zone_w, w_h)

    # TODO scroll line-by-line when an addr is displayed on multiple lines (eg labels/comments)
    # TODO selection

    update_line_text if @want_update_line_text
    update_caret if @want_update_caret

    if @parent_widget.bg_color_callback
      ly = 0
      @line_address.each { |a|
        if c = @parent_widget.bg_color_callback[a]
          draw_rectangle_color(c, @arrow_zone_w, ly*@font_height, w_w, @font_height)
        end
        ly += 1
      }
    end

    # current window position
    x = @arrow_zone_w + 1
    y = 0

    # renders a string at current cursor position with a color
    # must not include newline
    render = lambda { |str, color|
      # function ends when we write under the bottom of the listing
      next if not str or y >= w_h or x >= w_w
      draw_string_hl(color, x, y, str)
      x += str.length * @font_width
    }

    # draw caret line background
    draw_rectangle_color(:cursorline_bg, 0, @caret_y*@font_height, w_w, @font_height)

    @line_text_color.each { |a|
      a.each { |s, c| render[s, c] }
      x = @arrow_zone_w + 1
      y += @font_height
    }

    if focus?
      cx = @arrow_zone_w + @caret_x*@font_width+1
      cy = @caret_y*@font_height
      draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
    end

    paint_arrows
  end

  # draws the @arrows defined in paint_listing
  def paint_arrows
    return if @arrows.empty? or not @line_address[0]
    w_w, w_h = @arrow_zone_w, height

    slot_alloc = {}	# [y1, y2] => x slot	-- y1 <= y2
    # find a free x slot for the vertical side of the arrow
    max = (w_w-6)/3
    find_free = lambda { |y1, y2|
      y1, y2 = y2, y1 if y2 < y1
      slot_alloc[[y1, y2]] = (0...max).find { |off|
        not slot_alloc.find { |(oy1, oy2), oo|
          # return true if this slot cannot share with off
          next if oo != off	# not same slot => ok
          next if oy1 == y1 and y1 != 0		# same upbound & in window
          next if oy2 == y2 and y2 != w_h-1	# same lowbound & in window
          # check overlapping segment
          (y1 >= oy1 and y1 <= oy2) or
          (y2 >= oy1 and y2 <= oy2) or
          (oy1 >= y1 and oy1 <= y2) or
          (oy2 >= y1 and oy2 <= y2)
        }
      } || (max-1)
    }

    # alloc slots for arrows, starts by the smallest
    arrs = { :arrow_dn => [], :arrow_up => [], :arrow_hl => [] }
    @arrows.sort_by { |from, to|
      if from.kind_of? Numeric and to.kind_of? Numeric
        (from-to).abs
      else
        100000
      end
    }.each { |from, to|
      y1 = case from
      when :up; 0
      when :down; w_h-1
      else from * @font_height + @font_height/2 - 1
      end
      y2 = case to
      when :up; 0
      when :down; w_h-1
      else to * @font_height + @font_height/2 - 1
      end
      if y1 <= y2
        y1 += 2 if y1 != 0
      else
        y1 -= 2 if y1 != w_h-1
      end

      col = :arrow_dn
      col = :arrow_up if y1 > y2
      col = :arrow_hl if (from.kind_of? Integer and @line_address[from] == @line_address[@caret_y]) or
          (to.kind_of? Integer and @line_address[to] == @line_address[@caret_y])
      arrs[col] << [y1, y2, find_free[y1, y2]]
    }

    slot_w = (w_w-4)/slot_alloc.values.uniq.length
    # draw arrows (hl last to overwrite)
    [:arrow_dn, :arrow_up, :arrow_hl].each { |col|
      draw_color(col)
      arrs[col].each { |y1, y2, slot|
        x1 = w_w-1
        x2 = w_w-4 - slot*slot_w - slot_w/2

        draw_line(x1, y1, x2, y1) if y1 != 0 and y1 != w_h-1
        draw_line(x2, y1, x2, y2)
        draw_line(x2, y2, x1, y2) if y2 != 0 and y2 != w_h-1
        draw_line(x1, y2, x1-3, y2-3) if y2 != 0 and y2 != w_h-1
        draw_line(x1, y2, x1-3, y2+3) if y2 != 0 and y2 != w_h-1
      }
    }
  end

  # if curaddr points to an instruction, find the next data, else find the next instruction
  def move_to_next
    a = current_address
    if not @dasm.get_section_at(a)
      a = @dasm.sections.map { |k, e| k }.find_all { |k| k > a }.min
    elsif @dasm.di_at(a)
      while di = @dasm.di_at(a)
        a = di.block.list.last.next_addr
      end
    else
      a = @dasm.decoded.keys.find_all { |k| k > a }.min
    end
    @parent_widget.focus_addr(a) if a
  end

  # see move_to_next
  def move_to_prev
    a = current_address
    if not @dasm.get_section_at(a)
      a = @dasm.sections.map { |k, e| k }.find_all { |k| k < a }.max
      a += @dasm.get_section_at(a)[0].length - 1 if a
    elsif @dasm.di_at(a)
      while di = @dasm.di_at(a)
        a = di.block.list.first.address
        if off = (1..16).find { |off_|
            @dasm.decoded[a-off_].kind_of? DecodedInstruction and
            @dasm.decoded[a-off_].next_addr == a }
          a -= off
        else
          a -= 1
        end
      end
    else
      a = @dasm.decoded.keys.find_all { |k| k < a }.max
    end
    @parent_widget.focus_addr(a) if a
  end

  def keypress_ctrl(key)
    case key
    when ?n; move_to_next ; true
    when ?p; move_to_prev ; true
    else return false
    end
    true
  end

  def keypress(key)
    case key
    when ?u	# undef data formatting with ?d
      addr = current_address
      if not @dasm.decoded[addr] and @dasm.xrefs[addr].kind_of?(Xref)
        @dasm.xrefs.delete addr
        gui_update
      end
    when :left
      if @caret_x >= 1
        @caret_x -= 1
        update_caret
      end
    when :up
      if @caret_y > 1 or (@caret_y == 1 and @startaddr == @minaddr)
        @caret_y -= 1
      else
        adjust_startaddr(-1)
      end
      update_caret
    when :right
      if @caret_x < @line_text[@caret_y].to_s.length
        @caret_x += 1
        update_caret
      end
    when :down
      if @caret_y < @line_address.length-3 or (@caret_y < @line_address.length - 2 and @startaddr == @maxaddr)
        @caret_y += 1
      else
        if a = @line_address[0] and na = @line_address.find { |na_| na_ != a }
          @startaddr = na
          gui_update
        else
          adjust_startaddr(1)
        end
      end
      update_caret
    when :pgup
      adjust_startaddr(-15)
    when :pgdown
      @startaddr = @line_address[@line_address.length/2] || @startaddr + 15
      gui_update
    when :home
      @caret_x = 0
      update_caret
    when :end
      @caret_x = @line_text[@caret_y].to_s.length
      update_caret
    when :popupmenu
      rightclick(@caret_x*@font_width + @arrow_zone_w+1, @caret_y*@font_height)
    else return false
    end
    true
  end

  def get_cursor_pos
    [@startaddr, @caret_x, @caret_y]
  end

  def set_cursor_pos(p)
    @startaddr, @caret_x, @caret_y = p
    gui_update
  end

  # hint that the caret moved
  # redraws the caret, change the hilighted word, redraw if needed
  def update_caret
    if @want_update_line_text
      @want_update_caret = true
      return
    end
    return if not @line_text[@caret_y]
    @want_update_caret = false
    if update_hl_word(@line_text[@caret_y], @caret_x) or @oldcaret_y != @caret_y or true
      redraw
    else
      return if @oldcaret_x == @caret_x and @oldcaret_y == @caret_y

      invalidate_caret(@oldcaret_x, @oldcaret_y, @arrow_zone_w, 0)
      invalidate_caret(@caret_x, @caret_y, @arrow_zone_w, 0)

      if @arrows.find { |f, t| f == @caret_y or t == @caret_y or f == @oldcaret_y or t == @oldcaret_y }
        invalidate(0, 0, @arrow_zone_w, 1000000)
      end
    end
    @parent_widget.focus_changed_callback[] if @parent_widget.focus_changed_callback and @oldcaret_y != @caret_y

    @oldcaret_x = @caret_x
    @oldcaret_y = @caret_y
  end

  # focus on addr
  # addr may be a dasm label, dasm address, dasm address in string form (eg "0DEADBEEFh")
  # may scroll the window
  # returns true on success (address exists)
  def focus_addr(addr)
    return if not addr = @parent_widget.normalize(addr)
    if l = @line_address.index(addr) and l < @line_address.length - 4
      @caret_y, @caret_x = @line_address.rindex(addr), 0
    elsif addr.kind_of?(Integer) ? (addr >= @minaddr and addr <= @maxaddr) : @dasm.get_section_at(addr)
      @startaddr, @caret_x, @caret_y = addr, 0, 0
      adjust_startaddr
      @wantaddr = @startaddr
      @line_address[@caret_y] = @startaddr	# so that right after focus_addr(42) ; self.current_address => 42 (coverage sync)
    else
      return
    end
    update_caret
    true
  end

  # returns the address of the data under the cursor
  def current_address
    @line_address[@caret_y] || -1
  end

  # reads @dasm to update @line_text_color/@line_text/@line_address/@arrows
  def update_line_text
    @want_update_line_text = false

    w_h = (height + @font_height - 1) / @font_height

    curaddr = @startaddr

    @line_address.clear
    @line_text.clear
    @line_text_color.clear	# list of [str, color]

    line = 0

    # list of arrows to draw ([addr_from, addr_to])
    arrows_addr = []

    str_c = []

    nl = lambda {
      @line_address[line] = curaddr
      @line_text[line] = str_c.map { |s, c| s }.join
      @line_text_color[line] = str_c
      str_c = []
      line += 1
    }

    while line < w_h
      if di = @dasm.di_at(curaddr)
        if di.block_head?
          # render dump_block_header, add a few colors
          b_header = '' ; @dasm.dump_block_header(di.block) { |l| b_header << l ; b_header << ?\n if b_header[-1] != ?\n }
          b_header.each_line { |l|
            l.chomp!
            cmt = (l[0, 2] == '//' or l[-1] != ?:)
            str_c << [l, (cmt ? :comment : :label)]
            nl[]
          }
          # ary
          di.block.each_from_samefunc(@dasm) { |addr|
            addr = @dasm.normalize addr
            # block.list.last for delayslot
            next if ndi = @dasm.di_at(addr) and ndi.block.list.last.next_addr == curaddr
            arrows_addr << [addr, curaddr]
          }
        end
        if di.block.list.last == di
          # kikoo delayslot
          rdi = di.block.list[-[4, di.block.list.length].min, 4].reverse.find { |_di| _di.opcode.props[:setip] } || di
          di.block.each_to_samefunc(@dasm) { |addr|
            addr = @dasm.normalize addr
            next if di.next_addr == addr and (not rdi.opcode.props[:saveip] or rdi.block.to_subfuncret)
            arrows_addr << [rdi.address, addr]
          }
        end
        str_c << ["#{Expression[di.address]}    ", :address]
        if @raw_data_length.to_i > 0
          if s = @dasm.get_edata_at(curaddr)
            raw = s.read(di.bin_length)
            raw = raw.unpack('H*').first
          else
            raw = ''
          end
          raw = raw.ljust(@raw_data_length*2)[0, @raw_data_length*2]
          raw += (di.bin_length > @raw_data_length ? '-  ' : '   ')
          str_c << [raw, :raw_data]
        end
        str_c << ["#{di.instruction} ".ljust(di.comment ? 24 : 0), :instruction]
        str_c << [" ; #{di.comment.join(' ')}", :comment] if di.comment
        nl[]

        # instr overlapping
        if off = (1...di.bin_length).find { |off_| @dasm.decoded[curaddr + off_] }
          nl[]
          curaddr += off
          str_c << ["// ------ overlap (#{di.bin_length - off}) ------", :comment]
          nl[]
        else
          curaddr += [di.bin_length, 1].max
        end
      elsif s = @dasm.get_edata_at(curaddr) and s.ptr < s.length
        @dasm.comment[curaddr].each { |c| str_c << ["// #{c}", :comment] ; nl[] } if @dasm.comment[curaddr]
        if label = s.inv_export[s.ptr]
          l_list = @dasm.label_alias[curaddr].to_a.sort
          label = l_list.pop
          nl[] if not l_list.empty?
          l_list.each { |name|
            str_c << ["#{name}:", :label]
            nl[]
          }
        end

        len = 256
        comment = nil
        if s.data.length > s.ptr
          str = s.read(len).unpack('C*')
          s.ptr -= len		# we may not display the whole bunch, ptr is advanced later
          len = str.length
          if @dasm.xrefs[curaddr] or rel = s.reloc[s.ptr]
            xlen = nil
            xlen = rel.length if rel
            comment = []
            @dasm.each_xref(curaddr) { |xref|
              xlen ||= xref.len || 1 if xref.len
              comment << " #{xref.type}#{xref.len}:#{Expression[xref.origin]}" if xref.origin
            } if @dasm.xrefs[curaddr]
            len = xlen if xlen and xlen >= 2	# db xref may point a string
            comment = nil if comment.empty?
            len = (1..len).find { |l| @dasm.xrefs[curaddr+l] or s.inv_export[s.ptr+l] or s.reloc[s.ptr+l] } || len
            str = str[0, len] if len < str.length
            str = str.pack('C*').unpack(@dasm.cpu.endianness == :big ? 'n*' : 'v*') if xlen == 2
            if (xlen == 1 or xlen == 2) and asc = str.inject('') { |asc_, c|
                case c
                when 0x20..0x7e, 9, 10, 13; asc_ << c
                else break asc_
                end
              } and asc.length >= 1
              dat = "#{xlen == 1 ? 'db' : 'dw'} #{asc.inspect} "
              aoff = asc.length * xlen
            else
              len = 1 if (len != 2 and len != 4 and len != 8) or len < 1
              dat = "#{%w[x db dw x dd x x x dq][len]} #{Expression[s.decode_imm("u#{len*8}".to_sym, @dasm.cpu.endianness)]} "
              aoff = len
            end
          elsif asc = str.inject('') { |asc_, c|
            case c
            when 10; break asc_ << c
            when 0x20..0x7e, 9, 13; asc_ << c
            else break asc_
            end
          } and asc.length > 3
            len = asc.length
            len = (1..len).find { |l| @dasm.xrefs[curaddr+l] or s.inv_export[s.ptr+l] or s.reloc[s.ptr+l] } || len
            asc = asc[0, len]
            dat = "db #{asc.inspect} "
            aoff = asc.length
          elsif rep = str.inject(0) { |rep_, c|
            case c
            when str[0]; rep_+1
            else break rep_
            end
          } and rep > 4
            rep = (1..rep).find { |l| @dasm.xrefs[curaddr+l] or s.inv_export[s.ptr+l] or s.reloc[s.ptr+l] } || rep
            rep -= curaddr % 256 if rep == 256 and curaddr.kind_of? Integer
            dat = "db #{Expression[rep]} dup(#{Expression[str[0]]}) "
            aoff = rep
          else
            dat = "db #{Expression[str[0]]} "
            aoff = 1
          end
        else
          if @dasm.xrefs[curaddr]
            comment = []
            @dasm.each_xref(curaddr) { |xref|
              len = xref.len if xref.len
              comment << " #{xref.type}#{xref.len}:#{Expression[xref.origin] if xref.origin} "
            }
            len = 1 if (len != 2 and len != 4 and len != 8) or len < 1
            dat = "#{%w[x db dw x dd x x x dq][len]} ? "
            aoff = len
          else
            len = [len, s.length-s.ptr].min
            len -= curaddr % 256 if len == 256 and curaddr.kind_of? Integer
            len = (1..len).find { |l| @dasm.xrefs[curaddr+l] or s.inv_export[s.ptr+l] or s.reloc[s.ptr+l] } || len
            dat = "db #{Expression[len]} dup(?) "
            aoff = len
          end
        end
        str_c << ["#{Expression[curaddr]}    ", :address]
        if @raw_data_length.to_i > 0
          if s = @dasm.get_section_at(curaddr)
            raw = s[0].read([aoff, @raw_data_length].min)
            raw = raw.unpack('H*').first
          else
            raw = ''
          end
          raw = raw.ljust(@raw_data_length*2)
          raw += (aoff > @raw_data_length ? '-  ' : '   ')
          str_c << [raw, :raw_data]
        end
        str_c << ["#{label} ", :label] if label
        str_c << [dat.ljust(comment ? 24 : 0), :instruction]
        str_c << [" ; #{comment.join(' ')}", :comment] if comment
        nl[]
        curaddr += aoff
      else
        nl[]
        curaddr += 1
      end
    end
    @line_address[w_h..-1] = [] if @line_address.length >= w_h
    @caret_y = @line_address.rindex(@wantaddr) || @caret_y if @wantaddr
    @wantaddr = nil

    # convert arrows_addr to @arrows (with line numbers)
    # updates @arrows_widget if @arrows changed
    prev_arrows = @arrows
    addr_line = {}		# addr => last line (di)
    @line_address.each_with_index { |a, l| addr_line[a] = l }
    @arrows = arrows_addr.uniq.find_all { |from, to|
      ((from-curaddr)+(to-curaddr)).kind_of?(::Integer) rescue nil
    }.sort_by { |from, to|
      [from-curaddr, to-curaddr]
    }.map { |from, to|
      [(addr_line[from] || (from-curaddr < 0 ? :up : :down)),
       (addr_line[ to ] || (to - curaddr < 0 ? :up : :down))]
    }
    invalidate(0, 0, @arrow_zone_w, 100000) if prev_arrows != @arrows
  end

  def gui_update
    # allows a focus_addr after an operation that changed section addresses (eg rebase)
    addrs = @dasm.sections.keys.grep(Integer)
    @minaddr = addrs.min.to_i
    @maxaddr = (addrs.max + @dasm.sections[addrs.max].length rescue (1 << @dasm.cpu.size))

    @want_update_line_text = true
    redraw
  end
end
end
end
