#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
module Gui
class HexWidget < DrawableWidget
  # data_size = size of data in bytes (1 => chars, 4 => dwords..)
  # line_size = nr of bytes shown per line
  # view_addr = addr of 1st byte to display
  attr_accessor :dasm, :show_address, :show_data, :show_ascii,
    :data_size, :line_size, :endianness,
    #:data_sign, :data_hex,
    :caret_x_data, :focus_zone,
    :keep_aligned, :relative_addr, :hl_curbyte,
    :view_addr, :write_pending

  def initialize_widget(dasm, parent_widget)
    @dasm = dasm
    @parent_widget = parent_widget

    # @caret_x = caret position in octets
    # in hex, round to nearest @data_size and add @caret_x_data (nibbles)
    @x_data = 7
    @caret_x_data = 0
    @oldcaret_x_data = 42
    @focus_zone = @oldfocus_zone = :hex
    @addr_min = @dasm.sections.keys.grep(Integer).min rescue nil
    @addr_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
    @view_addr = @dasm.prog_binding['entrypoint'] || @addr_min || 0
    @show_address = @show_data = @show_ascii = true
    @data_size = 1
    @line_size = 16
    @num_lines = 2	# height of widget in lines
    @write_pending = {}	# addr -> newvalue (characters)
    @endianness = @dasm.cpu.endianness
    @raw_data_cache = {}	# addr -> raw @line_size data at addr
    #@data_sign = false
    #@data_hex = true
    @keep_aligned = false	# true to keep the topleft octet a multiple of linewidth
    @relative_addr = nil	# show '+42h' in the addr column if not nil
    @hl_curbyte = true	# draw grey bg for current byte

    @default_color_association = { :ascii => :black, :data => :black,
        :address => :blue, :caret => :black, :background => :white,
        :write_pending => :darkred, :caret_mirror => :palegrey }
  end

  def resized(w, h)
    wc = w/@font_width
    hc = h/@font_height
    ca = current_address
    @num_lines = hc
    @caret_y = hc-1 if @caret_y >= hc
    ols = @line_size
    @line_size = 8
    @line_size *= 2 while x_ascii+(@show_ascii ? @line_size : 0) < wc	# booh..
    @line_size /= 2
    if @line_size != ols
      @view_addr &= -@line_size if @keep_aligned
      focus_addr ca
      gui_update
    end
  end

  # converts a screen x coord (in characters) to a [@caret_x, @caret_x_data, @focus_zone]
  def chroff_to_caretx(x)
    if x < x_data
      [0, 0, (@show_data ? :hex : :ascii)]
    elsif x < x_ascii
      x -= x_data
      x -= x/(4*(2*@data_size+1)+1)	# remove space after each 4*@data_size
      x -= x/(2*@data_size+1)		# remove space after each @data_size
      x = 2*@line_size-1 if x >= 2*@line_size	# between hex & ascii
      cx = x/(2*@data_size)*@data_size
      cxd = x-2*cx
      [cx, cxd, :hex]
    elsif x < x_ascii+@line_size
      x -= x_ascii
      [x, 0, :ascii]
    else
      [@line_size-1, 0, (@show_ascii ? :ascii : :hex)]
    end
  end

  def click(x, y)
    @caret_x, @caret_x_data, @focus_zone = chroff_to_caretx((x-1).to_i / @font_width)
    @caret_y = y.to_i / @font_height
    update_caret
  end

  def rightclick(x, y)
    doubleclick(x, y)
  end

  def doubleclick(x, y)
    if x < @x_data * @font_width
      if @relative_addr
        @relative_addr = nil
      else
        @relative_addr = @view_addr
      end
    else
      @data_size = {1 => 2, 2 => 4, 4 => 8, 8 => 1}[@data_size]
    end
    redraw
  end

  def mouse_wheel(dir, x, y)
    off = height.to_i/@font_height/4*@line_size
    case dir
    when :up; @view_addr -= off
    when :down; @view_addr += off
    end
    gui_update
  end

  # returns 1 line of data
  def data_at(addr, len=@line_size)
    if len == @line_size and l = @raw_data_cache[addr]
      l
    elsif s = @dasm.get_section_at(addr)
      l = s[0].read(len)
      @raw_data_cache[addr] = l if len == @line_size
      l
    end
  end

  def paint
    w_h = height
    curaddr = @view_addr
    # current window position
    x = 1
    y = 0
    @num_lines = 0

    # renders a string at current cursor position with a color
    # must not include newline
    render = lambda { |str, color|
      draw_string_color(color, x, y, str)
      x += str.length * @font_width
    }

    if @show_address
      @x_data = [6, Expression[curaddr].to_s.length].max + 1
    end

    xd = x_data*@font_width + 1
    xa = x_ascii*@font_width + 1
    hexfmt = "%0#{@data_size*2}x "
    wp_win = {} # @write_pending clipped to current window
    if not @write_pending.empty?
      if curaddr.kind_of? Integer
        @write_pending.keys.grep(curaddr...curaddr+(w_h/@font_height+1)*@line_size).each { |k| wp_win[k] = @write_pending[k] }
      else wp_win = @write_pending.dup
      end
    end

    # draw text until screen is full
    while y < w_h
      if @show_address
        if @relative_addr
               diff = Expression[curaddr] - @relative_addr
               if diff.kind_of? Integer
            addr = "#{'+' if diff >= 0}#{Expression[diff]}".ljust(@x_data-1)
               else
            addr = "#{Expression[curaddr]}"
               end
        else
          addr = "#{Expression[curaddr]}"
        end
        render[addr.rjust(@x_data-1, '0'), :address]
      end

      d = data_at(curaddr)
      if not d and data_at(curaddr+@line_size-1, 1)
        # data in the current line but not from the beginning
        d_o = (1...@line_size).find { |o| d = data_at(curaddr+o, @line_size-o) }.to_i
      else
        d_o = 0
      end
      wp = {}
      d.length.times { |o|
        if c = wp_win[curaddr+d_o+o]
          wp[d_o+o] = true
          d = d.dup
          d[o, 1] = c.chr
        end
      } if d
      if @show_data and d
        x = xd
        if d_o > 0
          d_do = [0].pack('C')*(d_o % @data_size) + d
          i = d_o/@data_size
          x += (i*(@data_size*2+1) + i/4) * @font_width
        else
          d_do = d
          i = 0
        end
        # XXX non-hex display ? (signed int, float..)
        case @data_size
        when 1; pak = 'C*'
        when 2; pak = (@endianness == :little ? 'v*' : 'n*')
        when 4; pak = (@endianness == :little ? 'V*' : 'N*')
        when 8; pak = 'Q*'	# XXX endianness..
        end
        awp = {} ; wp.each_key { |k| awp[k/@data_size] = true }

        if @hl_curbyte and @caret_y == y/@font_height
          cx = (x_data + x_data_cur(@caret_x, 0))*@font_width + 1
          draw_rectangle_color(:caret_mirror, cx, y, @data_size*2*@font_width, @font_height)
        end

        if awp.empty?
          s = ''
          d_do.unpack(pak).each { |b|
            s << (hexfmt % b)
            s << ' ' if i & 3 == 3
            i += 1
          }
          render[s, :data]
        else
          d_do.unpack(pak).each { |b|
            col = awp[i] ? :write_pending : :data
            render[hexfmt % b, col]
            render[' ', :data] if i & 3 == 3
            i+=1
          }
        end
      end
      if @show_ascii and d
        x = xa + d_o*@font_width
        d = d.gsub(/[^\x20-\x7e]/, '.')
        if wp.empty?
          render[d, :ascii]
        else
          d.length.times { |o|
            col = wp[o] ? :write_pending : :ascii
            render[d[o, 1], col]
          }
        end
      end

      curaddr += @line_size
      @num_lines += 1
      x = 1
      y += @font_height
    end

    # draw caret
    if @show_data
      cx = (x_data + x_data_cur)*@font_width+1
      cy = @caret_y*@font_height
      col = (focus? && @focus_zone == :hex) ? :caret : :caret_mirror
      draw_line_color(col, cx, cy, cx, cy+@font_height-1)
    end

    if @show_ascii
      cx = (x_ascii + @caret_x)*@font_width+1
      cy = @caret_y*@font_height
      col = (focus? && @focus_zone == :ascii) ? :caret : :caret_mirror
      draw_line_color(col, cx, cy, cx, cy+@font_height-1)
    end

    @oldcaret_x, @oldcaret_y, @oldcaret_x_data, @oldfocus_zone = @caret_x, @caret_y, @caret_x_data, @focus_zone
  end

  # char x of start of data zone
  def x_data
    @show_address ? @x_data : 0
  end

  # char x of start of ascii zone
  def x_ascii
    x_data + (@show_data ? @line_size*2 + @line_size/@data_size + @line_size/@data_size/4 : 0)
  end

  # current offset in data zone of caret
  def x_data_cur(cx = @caret_x, cxd = @caret_x_data)
    x = (cx/@data_size)*@data_size
    2*x + x/@data_size + x/@data_size/4 + cxd
  end

  def keypress(key)
    case key
    when :left
      key_left
      update_caret
    when :right
      key_right
      update_caret
    when :up
      key_up
      update_caret
    when :down
      key_down
      update_caret
    when :pgup
      if not @addr_min or @view_addr > @addr_min
        @view_addr -= (@num_lines/2)*@line_size
        gui_update
      end
    when :pgdown
      if not @addr_max or @view_addr < @addr_max
        @view_addr += (@num_lines/2)*@line_size
        gui_update
      end
    when :home
      @caret_x = 0
      update_caret
    when :end
      @caret_x = @line_size-1
      update_caret

    when :backspace
      key_left
      if @focus_zone == :hex
        key_left if @caret_x_data & 1 == 1
        oo = @caret_x_data/2
        oo = @data_size - oo - 1 if @endianness == :little
        @write_pending.delete current_address + oo
      else
        @write_pending.delete current_address
      end
      redraw
    when :tab
      switch_focus_zone
      update_caret
    when :enter
      commit_writes
      gui_update
    when :esc
      if not @write_pending.empty?
        @write_pending.clear
        redraw
      else return false
      end

    when ?\x20..?\x7e
      if @focus_zone == :hex
        if ?a.kind_of?(String)	# ruby1.9
          v = key.ord
          case key
          when ?0..?9; v -= ?0.ord
          when ?a..?f; v -= ?a.ord-10
          when ?A..?F; v -= ?A.ord-10
          else return false
          end
        else
          case v = key
          when ?0..?9; v -= ?0
          when ?a..?f; v -= ?a-10
          when ?A..?F; v -= ?A-10
          else return false
          end
        end

        oo = @caret_x_data/2
        oo = @data_size - oo - 1 if @endianness == :little
        baddr = current_address + oo
        return false if not d = data_at(baddr, 1)
        o = 4*((@caret_x_data+1) % 2)
        @write_pending[baddr] ||= d[0]
        if ?a.kind_of?(String)
          @write_pending[baddr] = ((@write_pending[baddr].ord & ~(0xf << o)) | (v << o)).chr
        else
          @write_pending[baddr] = (@write_pending[baddr] & ~(0xf << o)) | (v << o)
        end
      else
        @write_pending[current_address] = key
      end
      key_right
      redraw
    else return false
    end
    true
  end

  def keypress_ctrl(key)
    case key
    when ?f
      if @focus_zone == :hex
        prompt_search_hex
      else
        prompt_search_ascii
      end
    else return false
    end
    true
  end

  # pop a dialog, scans the sections for a hex pattern
  def prompt_search_hex
    inputbox('hex pattern to search (hex regexp, use .. for wildcard)') { |pat|
      pat = pat.gsub(' ', '').gsub('..', '.').gsub(/[0-9a-f][0-9a-f]/i) { |o| "\\x#{o}" }
      pat = Regexp.new(pat, Regexp::MULTILINE, 'n')	# 'n' = force ascii-8bit
      list = [['addr']] + @dasm.pattern_scan(pat).map { |a| [Expression[a]] }
      listwindow("hex search #{pat}", list) { |i| focus_addr i[0] }
    }
  end

  # pop a dialog, scans the sections for a regex
  def prompt_search_ascii
    inputbox('data pattern to search (regexp)') { |pat|
      list = [['addr']] + @dasm.pattern_scan(/#{pat}/).map { |a| [Expression[a]] }
      listwindow("data search #{pat}", list) { |i| focus_addr i[0] }
    }
  end

  def key_left
    if @focus_zone == :hex
      if @caret_x_data > 0
        @caret_x_data -= 1
      else
        @caret_x_data = @data_size*2-1
        @caret_x -= @data_size
      end
    else
      @caret_x -= 1
    end
    if @caret_x < 0
      @caret_x += @line_size
      key_up
    end
  end

  def key_right
    if @focus_zone == :hex
      if @caret_x_data < @data_size*2-1
        @caret_x_data += 1
      else
        @caret_x_data = 0
        @caret_x += @data_size
      end
    else
      @caret_x += 1
    end
    if @caret_x >= @line_size
      @caret_x = 0
      key_down
    end
  end

  def key_up
    if @caret_y > 0
      @caret_y -= 1
    elsif not @addr_min or @view_addr > @addr_min
      @view_addr -= @line_size
      redraw
    else
      @caret_x = @caret_x_data = 0
    end
  end

  def key_down
    if @caret_y < @num_lines-2
      @caret_y += 1
    elsif not @addr_max or @view_addr < @addr_max
      @view_addr += @line_size
      redraw
    else
      @caret_x = @line_size-1		# XXX partial final line... (01 23 45         bla    )
      @caret_x_data = @data_size*2-1
    end
  end

  def switch_focus_zone(n=nil)
    n ||= { :hex => :ascii, :ascii => :hex }[@focus_zone]
    @caret_x = @caret_x / @data_size * @data_size if n == :hex
    @caret_x_data = 0
    @focus_zone = n
  end

  def commit_writes
    a = s = nil
    @write_pending.each { |k, v|
      if not s or k < a or k >= a + s.length
        s, a = @dasm.get_section_at(k)
      end
      next if not s
      s[k-a] = v
    }
    @write_pending.clear
  rescue
    @parent_widget.messagebox($!, $!.class.to_s)
  end

  def get_cursor_pos
    [@view_addr, @caret_x, @caret_y, @caret_x_data, @focus_zone]
  end

  def set_cursor_pos(p)
    @view_addr, @caret_x, @caret_y, @caret_x_data, @focus_zone = p
    redraw
    update_caret
  end

  # hint that the caret moved
  def update_caret
    return redraw if @hl_curbyte
    a = []
    a << [x_data + x_data_cur, @caret_y] << [x_data + x_data_cur(@oldcaret_x, @oldcaret_x_data), @oldcaret_y] if @show_data
    a << [x_ascii + @caret_x, @caret_y] << [x_ascii + @oldcaret_x, @oldcaret_y] if @show_ascii
    a.each { |x, y| invalidate_caret(x, y) }
    @oldcaret_x, @oldcaret_y, @oldcaret_x_data, @oldfocus_zone = @caret_x, @caret_y, @caret_x_data, @focus_zone
  end

  # focus on addr
  # returns true on success (address exists)
  def focus_addr(addr)
    return if not addr = @parent_widget.normalize(addr)
    if addr.kind_of? Integer
      return if @addr_min and (addr < @addr_min or addr > @addr_max)
      addr &= -@line_size if @keep_aligned
      @view_addr = addr if addr < @view_addr or addr >= @view_addr+(@num_lines-2)*@line_size
    elsif s = @dasm.get_section_at(addr)
      @view_addr = Expression[s[1]]
    else return
    end
    @caret_x = (addr-@view_addr) % @line_size
    @caret_x_data = 0
    @caret_y = (addr-@view_addr) / @line_size
    @focus_zone = :ascii
    redraw
    update_caret
    true
  end

  # returns the address of the data under the cursor
  def current_address
    @view_addr + @caret_y.to_i*@line_size + @caret_x.to_i
  end

  def gui_update
    @addr_min = @dasm.sections.keys.grep(Integer).min rescue nil
    @addr_max = @dasm.sections.map { |s, e| s + e.length }.max rescue nil
    @raw_data_cache.clear
    redraw
  end
end
end
end
