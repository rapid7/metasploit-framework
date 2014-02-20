#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class AsmOpcodeWidget < DrawableWidget
  attr_accessor :dasm
  # nr of raw data bytes to display next to decoded instructions
  attr_accessor :raw_data_length
  
  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    @raw_data_length = 5

    @line_text = {}
    @line_address = {}
    @view_min = @dasm.sections.keys.min rescue nil
    @view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
    @view_addr = @dasm.prog_binding['entrypoint'] || @view_min || 0

    @default_color_association = { :comment => :darkblue, :label => :darkgreen, :text => :black,
      :instruction => :black, :address => :blue, :caret => :black, :raw_data => :black,
      :background => :white, :cursorline_bg => :paleyellow, :hl_word => :palered }
  end

  def resized(w, h)
    w /= @font_width
    h /= @font_height
    @caret_x = w-1 if @caret_x >= w
    @caret_y = h-1 if @caret_y >= h
  end

  def click(x, y)
    @caret_x = (x-1).to_i / @font_width
    @caret_y = y.to_i / @font_height
    update_caret
  end

  def rightclick(x, y)
    click(x, y)
    @parent_widget.clone_window(@hl_word, :opcodes)
  end

  def doubleclick(x, y)
    click(x, y)
    @parent_widget.focus_addr(@hl_word)
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up; (height/@font_height/4).times { scrollup }
    when :down; (height/@font_height/4).times { scrolldown }
    end
  end

  def di_at(addr)
    s = @dasm.get_section_at(addr) and s[0].ptr < s[0].length and update_di_args(@dasm.cpu.decode_instruction(s[0], addr))
  end

  def update_di_args(di)
    if di
      di.instruction.args.map! { |e|
        next e if not e.kind_of? Expression
        @dasm.get_label_at(e) || e
      }
    end
    di
  end

  def scrollup
    return if @view_min and @view_addr < @view_min
    # keep current instrs in sync
    16.times { |o|
      o += 1
      if di = di_at(@view_addr-o) and di.bin_length == o
        @view_addr -= o
        @line_address = {}
        redraw
        return
      end
    }
    @view_addr -= 1
    @line_address = {}
    redraw
  end

  def scrolldown
    return if @view_max and @view_addr >= @view_max
    if di = di_at(@view_addr)
      @view_addr += di.bin_length
    else
      @view_addr += 1
    end
    @line_address = {}
    redraw
  end

  def paint
    # draw caret line background
    draw_rectangle_color(:cursorline_bg, 0, @caret_y*@font_height, width, @font_height)

    want_update_caret = true if @line_address == {}

    # map lineno => address shown
    @line_address = Hash.new(-1)
    # map lineno => raw text
    @line_text = Hash.new('')

    # current address drawing
    curaddr = @view_addr
    # current line text buffer
    fullstr = ''
    # current line number
    line = 0
    # current window position
    x = 1
    y = 0

    # renders a string at current cursor position with a color
    # must not include newline
    render = lambda { |str, color|
      fullstr << str
      if @hl_word
        stmp = str
        pre_x = 0
        while stmp =~ /^(.*?)(\b#{Regexp.escape @hl_word}\b)/
          s1, s2 = $1, $2
          pre_x += s1.length * @font_width
          hl_x = s2.length * @font_width
          draw_rectangle_color(:hl_word, x+pre_x, y, hl_x, @font_height)
          pre_x += hl_x
          stmp = stmp[s1.length+s2.length..-1]
        end
      end
      draw_string_color(color, x, y, str)
      x += str.length * @font_width
    }

    # newline: current line is fully rendered, update @line_address/@line_text etc
    nl = lambda {
      @line_text[line] = fullstr
      @line_address[line] = curaddr
      fullstr = ''
      line += 1
      x = 1
      y += @font_height
    }

    invb = @dasm.prog_binding.invert

    # draw text until screen is full
    while y < height
      if label = invb[curaddr]
        nl[]
        @dasm.label_alias[curaddr].to_a.each { |name|
          render["#{name}:", :label]
          nl[]
        }
      end
      render["#{Expression[curaddr]}    ", :address]

      if di = di_at(curaddr)
        if @raw_data_length.to_i > 0
          if s = @dasm.get_section_at(curaddr)
            raw = s[0].read(di.bin_length)
            raw = raw.unpack('H*').first
          else
            raw = ''
          end
          raw = raw.ljust(@raw_data_length*2)[0, @raw_data_length*2]
          raw += (di.bin_length > @raw_data_length ? '-  ' : '   ')
          render[raw, :raw_data]
        end
        render["#{di.instruction} ", :instruction]
      else
        if s = @dasm.get_section_at(curaddr) and s[0].ptr < s[0].length
          render["db #{Expression[s[0].read(1).unpack('C')]} ", :instruction]
        end
      end
      nl[]
      curaddr += di ? di.bin_length : 1
    end

    if focus?
      # draw caret
      cx = @caret_x*@font_width+1
      cy = @caret_y*@font_height
      draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
    end

    update_caret if want_update_caret
  end

  def keypress(key)
    case key
    when :left
      if @caret_x >= 1
        @caret_x -= 1
        update_caret
      end
    when :up
      if @caret_y >= 1
        @caret_y -= 1
      else
        scrollup
      end
      update_caret
    when :right
      if @caret_x <= @line_text.values.map { |s| s.length }.max
        @caret_x += 1
        update_caret
      end
    when :down
      if @caret_y < @line_text.length-3
        @caret_y += 1
      else
        scrolldown
      end
      update_caret
    when :pgup
      (height/@font_height/2).times { scrollup }
    when :pgdown
      @view_addr = @line_address.fetch(@line_address.length/2, @view_addr+15)
      redraw
    when :home
      @caret_x = 0
      update_caret
    when :end
      @caret_x = @line_text[@caret_y].length
      update_caret
    else return false
    end
    true
  end

  def get_cursor_pos
    [@view_addr, @caret_x, @caret_y]
  end

  def set_cursor_pos(p)
    @view_addr, @caret_x, @caret_y = p
    redraw
    update_caret
  end

  # hint that the caret moved
  # redraws the caret, change the hilighted word, redraw if needed
  def update_caret
    if update_hl_word(@line_text[@caret_y], @caret_x) or @caret_y != @oldcaret_y
      redraw 
    elsif @oldcaret_x != @caret_x
      invalidate_caret(@oldcaret_x, @oldcaret_y)
      invalidate_caret(@caret_x, @caret_y)
    end

    @oldcaret_x, @oldcaret_y = @caret_x, @caret_y
  end

  # focus on addr
  # returns true on success (address exists)
  def focus_addr(addr)
    return if not addr = @parent_widget.normalize(addr)
    if l = @line_address.index(addr) and l < @line_address.keys.max - 4
      @caret_y, @caret_x = @line_address.keys.find_all { |k| @line_address[k] == addr }.max, 0
    elsif @dasm.get_section_at(addr)
      @view_addr, @caret_x, @caret_y = addr, 0, 0
      redraw
    else
      return
    end
    update_caret
    true
  end

  # returns the address of the data under the cursor
  def current_address
    @line_address[@caret_y]
  end

  def gui_update
    @view_min = @dasm.sections.keys.min rescue nil
    @view_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
    redraw
  end
end
end
end
