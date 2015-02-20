#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/gui/dasm_main'

module Metasm
module Gui

# TODO invalidate dbg.disassembler on selfmodifying code
class DbgWidget < ContainerVBoxWidget
  attr_accessor :dbg, :console, :regs, :code, :mem, :win
  attr_accessor :watchpoint
  attr_accessor :parent_widget, :keyboard_callback, :keyboard_callback_ctrl
  def initialize_widget(dbg)
    @dbg = dbg
    @keyboard_callback = {}
    @keyboard_callback_ctrl = {}
    @parent_widget = nil

    @regs = DbgRegWidget.new(dbg, self)
    @mem  = DisasmWidget.new(dbg.disassembler)
    @code = DisasmWidget.new(dbg.disassembler)	# after mem so that dasm.gui == @code
    @console = DbgConsoleWidget.new(dbg, self)
    @code.parent_widget = self
    @mem.parent_widget = self
    @dbg.disassembler.disassemble_fast(@dbg.pc)

    oldcb = @code.bg_color_callback
    @code.bg_color_callback = lambda { |a|
      if a == @dbg.pc
        :red_bg
        # TODO breakpoints & stuff
      elsif oldcb; oldcb[a]
      end
    }
    # TODO popup menu, set bp, goto here, show arg in memdump..

    @children = [@code, @mem, @regs]

    add @regs, 'expand' => false	# XXX
    add @mem
    add @code
    add @console

    @watchpoint = { @code => @dbg.register_pc }

    pc = @dbg.resolve_expr(@watchpoint[@code])
    graph = :graph if @dbg.disassembler.function_blocks(pc).to_a.length < 100
    @code.focus_addr(pc, graph, true)
    @mem.focus_addr(0, :hex, true)
  end

  def swapin_tid
    @regs.swapin_tid
    @dbg.disassembler.disassemble_fast(@dbg.pc)
    @children.each { |c|
      if wp = @watchpoint[c]
        c.focus_addr @dbg.resolve_expr(wp), nil, true
      end
    }
    redraw
  end

  def swapin_pid
    @mem.dasm = @dbg.disassembler
    @code.dasm = @dbg.disassembler
    swapin_tid
    gui_update
  end

  def keypress(key)
    return true if @keyboard_callback[key] and @keyboard_callback[key][key]
    case key
    when :f5;  protect { dbg_continue }
    when :f10; protect { dbg_stepover }
    when :f11; protect { dbg_singlestep }
    when :f12; protect { dbg_stepout }
    when ?.; @console.grab_focus
    else return @parent_widget ? @parent_widget.keypress(key) : false
    end
    true
  end

  def keypress_ctrl(key)
    return true if @keyboard_callback_ctrl[key] and @keyboard_callback_ctrl[key][key]
    case key
    when :f5;  protect { @dbg.pass_current_exception ; dbg.continue }
    else return @parent_widget ? @parent_widget.keypress_ctrl(key) : false
    end
    true
  end

  def pre_dbg_run
    @regs.pre_dbg_run
  end

  # TODO check_target always, incl when :stopped
  def post_dbg_run
    # focus currently stopped threads
    if @dbg.state == :running and tt = @dbg.tid_stuff.find { |tid, tstuff| tstuff[:state] != :running }
      @dbg.tid = tt[0]
    end

    want_redraw = true
    return if @idle_checking ||= nil	# load only one bg proc
    @idle_checking = true
    Gui.idle_add {
        protect {
      @dbg.check_target
      if @dbg.state == :running
        redraw if want_redraw	# redraw once if the target is running (less flicker with singlestep)
        want_redraw = false
        sleep 0.01
        next true
      end
      @idle_checking = false
      @dbg.dasm_invalidate
      @mem.gui_update
      @dbg.disassembler.sections.clear if @dbg.state == :dead
      @dbg.disassembler.disassemble_fast(@dbg.pc)
      @children.each { |c|
        if wp = @watchpoint[c]
          c.focus_addr @dbg.resolve_expr(wp), nil, true
        end
      }
      redraw
      false
        }
    }
  end

  def wrap_run
    pre_dbg_run
    yield
    post_dbg_run
  end

  def dbg_continue(*a) wrap_run { @dbg.continue(*a) } end
  def dbg_singlestep(*a) wrap_run { @dbg.singlestep(*a) } end
  def dbg_stepover(*a) wrap_run { @dbg.stepover(*a) } end
  def dbg_stepout(*a) wrap_run { @dbg.stepout(*a) } end

  def redraw
    super
    @console.redraw
    @regs.gui_update
    @children.each { |c| c.redraw }
  end

  def gui_update
    @console.redraw
    @children.each { |c| c.gui_update }
  end

  def prompt_attach(caption='chose target')
    l = nil
    i = inputbox(caption) { |name|
      i = nil ; l.destroy if l and not l.destroyed?
      @dbg.attach(name)
    }

    # build process list in bg (exe name resolution takes a few seconds)
    list = [['pid', 'name']]
    list_pr = OS.current.list_processes
    Gui.idle_add {
      if pr = list_pr.shift
        list << [pr.pid, pr.path] if pr.path
        true
      elsif i
        me = ::Process.pid.to_s
        l = listwindow('running processes', list,
                 :noshow => true,
                 :color_callback => lambda { |le| [:grey, :palegrey] if le[0] == me }
                ) { |e|
                  i.text = e[0]
                  i.keypress(:enter) if l.destroyed?
                }
                l.x += l.width
                l.show
                false
      end
    } if not list_pr.empty?
  end

  def prompt_createprocess(caption='chose path')
    openfile(caption) { |path|
      path = '"' + path + '"' if @dbg.shortname == 'windbg' and path =~ /\s/
      inputbox('target args?', :text => path) { |pa|
        @dbg.create_process(pa)
      }
    }
  end

  def prompt_datawatch
    inputbox('data watch', :text => @watchpoint[@mem].to_s) { |e|
      case e
      when '', 'nil', 'none', 'delete'
        @watchpoint.delete @mem
      else
        @watchpoint[@mem] = @console.parse_expr(e)
      end
    }
  end

  def dragdropfile(f)
    case f
    when /\.(c|h|cpp)$/; @dbg.disassembler.parse_c_file(f)
    when /\.map$/; @dbg.load_map(f)
    when /\.rb$/; @dbg.load_plugin(f) ; @console.add_log "loaded plugin #{File.basename(f, '.rb')}"
    else messagebox("unsupported file extension #{f}")
    end
  end

  def extend_contextmenu(tg, menu, addr=nil)
    if addr
      bm = tg.new_menu
      bl = @dbg.all_breakpoints(addr)
      if not bl.empty?
        tg.addsubmenu(bm, '_clear breakpoint') { bl.each { |b| @dbg.del_bp(b) } }
      end
      tg.addsubmenu(bm, '_go here') { @dbg.bpx(addr, true) ; dbg_continue }
      tg.addsubmenu(bm, '_bpx') { @dbg.bpx(addr) }
      tg.addsubmenu(bm, 'bpm _read') { @dbg.hwbp(addr, :r, 1) }
      tg.addsubmenu(bm, 'bpm _write') { @dbg.hwbp(addr, :w, 1) }
      tg.addsubmenu(menu, '_bp', bm)
    end
    if @parent_widget.respond_to?(:extend_contextmenu)
      @parent_widget.extend_contextmenu(tg, menu, addr)
    end
  end
end


# a widget that displays values of registers of a Debugger
# also controls the Debugger and commands slave windows (showing listing & memory)
class DbgRegWidget < DrawableWidget
  attr_accessor :dbg

  def initialize_widget(dbg, parent_widget)
    @dbg = dbg
    @parent_widget = parent_widget

    @caret_x = @caret_reg = 0
    @oldcaret_x = @oldcaret_reg = 42

    @tid_stuff = {}
    swapin_tid

    @reg_pos = []	# list of x y w h vx of the reg drawing on widget, vx is x of value

    @default_color_association = ColorTheme.merge :label => :text, :data => :blue, :write_pending => :darkred,
        :changed => :green, :caret => :text, :inactive => :palegrey
  end

  def swapin_tid
    stf = @tid_stuff[[@dbg.pid, @dbg.tid]] ||= {}
    return if not @dbg.cpu
    @write_pending = stf[:write_pending] ||= {}	# addr -> newvalue (bytewise)
    @registers = stf[:registers] ||= @dbg.register_list
    @flags = stf[:flags] ||= @dbg.flag_list
    @register_size = stf[:reg_sz] ||= @registers.inject(Hash.new(1)) { |h, r| h.update r => @dbg.register_size[r]/4 }
    @reg_cache = stf[:reg_cache] ||= Hash.new(0)
    @reg_cache_old = stf[:reg_cache_old] ||= {}
  end

  def initialize_visible
    gui_update
  end

  def click(ex, ey)
    if p = @reg_pos.find { |x, y, w, h, vx| x <= ex and x+w >= ex and y <= ey and y+h >= ey }
      @caret_reg = @reg_pos.index(p)
      @caret_x = ((ex - p[4]) / @font_width).to_i
      rs = @register_size[@registers[@caret_reg]]
      @caret_x = rs-1 if @caret_x > rs-1
      @caret_x = 0 if @caret_x < 0
      update_caret
    end
  end

  def rightclick(x, y)
    doubleclick(x, y)	# XXX
  end

  def doubleclick(x, y)
    gui_update	# XXX
  end

  def paint
    x = 1
    y = 0

    w_w = width

    render = lambda { |str, color|
      draw_string_color(color, x, y, str)
      x += str.length * @font_width
    }

    @reg_pos = []
    running = (@dbg.state != :stopped)
    regstrlen = @registers.map { |reg| reg.to_s.length + 1 }.max
    @registers.each { |reg|
      strlen = regstrlen + @register_size[reg]
      if x + strlen*@font_width >= w_w
        x = 1
        y += @font_height
      end
      @reg_pos << [x, y, (strlen+1)*@font_width, @font_height, x+regstrlen*@font_width]

      render["#{reg}=".ljust(regstrlen), :label]
      v = @write_pending[reg] || @reg_cache[reg]
      col = running ? :inactive : @write_pending[reg] ? :write_pending : @reg_cache_old.fetch(reg, v) != v ? :changed : :data
      render["%0#{@register_size[reg]}x " % v, col]
      x += @font_width	# space
    }

    @flags.each { |reg|
      if x + @font_width >= w_w	# XXX nowrap flags ?
        x = 1
        y += @font_height
      end
      @reg_pos << [x, y, @font_width, @font_height, x]

      v = @write_pending[reg] || @reg_cache[reg]
      col = running ? :inactive : @write_pending[reg] ? :write_pending : @reg_cache_old.fetch(reg, v) != v ? :changed : :data
      v = v == 0 ? reg.to_s.downcase : reg.to_s.upcase
      render[v, col]
      x += @font_width	# space
    }

    if focus?
      # draw caret
      cx = @reg_pos[@caret_reg][4] + @caret_x*@font_width
      cy = @reg_pos[@caret_reg][1]
      draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
    end

    @oldcaret_x, @oldcaret_reg = @caret_x, @caret_reg

    @parent_widget.resize_child(self, width, y+@font_height)
  end

  # keyboard binding
  # basic navigation (arrows, pgup etc)
  def keypress(key)
    case key
    when :left
      if @caret_x > 0
        @caret_x -= 1
        update_caret
      end
    when :right
      if @caret_x < @register_size[@registers[@caret_reg]]-1
        @caret_x += 1
        update_caret
      end
    when :up
      if @caret_reg > 0
        @caret_reg -= 1
      else
        @caret_reg = @registers.length+@flags.length-1
      end
      @caret_x = 0
      update_caret
    when :down
      if @caret_reg < @registers.length+@flags.length-1
        @caret_reg += 1
      else
        @caret_reg = 0
      end
      @caret_x = 0
      update_caret
    when :home
      @caret_x = 0
      update_caret
    when :end
      @caret_x = @register_size[@registers[@caret_reg]]-1
      update_caret
    when :tab
      if @caret_reg < @registers.length+@flags.length-1
        @caret_reg += 1
      else
        @caret_reg = 0
      end
      @caret_x = 0
      update_caret
    when :backspace
      # TODO
    when :enter
      commit_writes
      redraw
    when :esc
      @write_pending.clear
      redraw

    when ?\x20..?\x7e
      if ?a.kind_of?(String)
        v = key.ord
        case key
        when ?\x20; v = nil	# keep current value
        when ?0..?9; v -= ?0.ord
        when ?a..?f; v -= ?a.ord-10
        when ?A..?F; v -= ?A.ord-10
        else return false
        end
      else
        case v = key
        when ?\x20; v = nil
        when ?0..?9; v -= ?0
        when ?a..?f; v -= ?a-10
        when ?A..?F; v -= ?A-10
        else return false
        end
      end

      reg = @registers[@caret_reg] || @flags[@caret_reg-@registers.length]
      rsz = @register_size[reg]
      if v and rsz != 1
        oo = 4*(rsz-@caret_x-1)
        ov = @write_pending[reg] || @reg_cache[reg]
        ov &= ~(0xf << oo)
        ov |= v << oo
        @write_pending[reg] = ov
      elsif v and (v == 0 or v == 1)	# TODO change z flag by typing 'z' or 'Z'
        @write_pending[reg] = v
        rsz = 1
      end

      if rsz == 1
        @caret_reg += 1
        @caret_reg = @registers.length if @caret_reg >= @registers.length + @flags.length
      elsif @caret_x < rsz-1
        @caret_x += 1
      else
        @caret_x = 0
      end
      redraw
    else return false
    end
    true
  end

  def pre_dbg_run
    @reg_cache_old.replace @reg_cache if @reg_cache
  end

  def commit_writes
    @write_pending.each { |k, v|
      if @registers.index(k)
        @dbg.set_reg_value(k, v)
      else
        @dbg.set_flag_value(k, v)
      end
      @reg_cache[k] = v
    }
    @write_pending.clear
  end

  def gui_update
    @reg_cache.replace @registers.inject({}) { |h, r| h.update r => @dbg.get_reg_value(r) }
    @flags.each { |f| @reg_cache[f] = @dbg.get_flag_value(f) }
    redraw
  end

  # hint that the caret moved
  def update_caret
    return if @oldcaret_x == @caret_x and @oldcaret_reg == @caret_reg

    invalidate_caret(@oldcaret_x, 0, *@reg_pos[@oldcaret_reg].values_at(4, 1))
    invalidate_caret(@caret_x, 0, *@reg_pos[@caret_reg].values_at(4, 1))

    @oldcaret_x, @oldcaret_reg = @caret_x, @caret_reg
  end

end


# a widget that displays logs of the debugger, and a cli interface to the dbg
class DbgConsoleWidget < DrawableWidget
  attr_accessor :dbg, :cmd_history, :log, :statusline, :commands, :cmd_help

  def initialize_widget(dbg, parent_widget)
    @dbg = dbg
    @parent_widget = parent_widget
    @dbg.gui = self

    @log = []
    @log_length = 4000
    @log_offset = 0
    @curline = ''
    @statusline = 'type \'help\' for help'
    @cmd_history = ['']
    @cmd_history_length = 200	# number of past commands to remember
    @cmd_histptr = nil

    @dbg.set_log_proc { |l| add_log l }

    @default_color_association = ColorTheme.merge :log => :palegrey, :curline => :white, :caret => :yellow,
      :background => :black, :status => :black, :status_bg => '088'

    init_commands
  end

  def initialize_visible
    grab_focus
    gui_update
  end

  def swapin_tid
    @parent_widget.swapin_tid
  end

  def swapin_pid
    @parent_widget.swapin_pid
  end

  def click(x, y)
    @caret_x = (x-1).to_i / @font_width - 1
    @caret_x = [[@caret_x, 0].max, @curline.length].min
    update_caret
  end

  def doubleclick(x, y)
    # TODO real copy/paste
    # for now, copy the line under the dblclick
    y -= height % @font_height
    y = y.to_i / @font_height
    hc = height / @font_height
    if y == hc - 1
      txt = @statusline
    elsif y == hc - 2
      txt = @curline
    else
      txt = @log.reverse[@log_offset + hc - y - 3].to_s
    end
    clipboard_copy(txt)
  end

  # copy/paste word under cursor (paste when on last line)
  def rightclick(x, y)
    y -= height % @font_height
    y = y.to_i / @font_height
    hc = height / @font_height
    x /= @font_width
    if y >= hc - 2
      keypress_ctrl ?v
    else
      txt = @log.reverse[@log_offset + hc - y - 3].to_s
      word = txt[0...x].to_s[/\w*$/] << txt[x..-1].to_s[/^\w*/]
      clipboard_copy(word)
    end
  end

  def mouse_wheel(dir, x, y)
    case dir
    when :up; @log_offset += 3
    when :down; @log_offset -= 3
    end
    redraw
  end

  def paint
    y = height

    render = lambda { |str, color|
      draw_string_color(color, 1, y, str)
      y -= @font_height
    }

    w_w = width

    y -= @font_height
    draw_rectangle_color(:status_bg, 0, y, w_w, @font_height)
    str = "#{@dbg.pid}:#{@dbg.tid} #{@dbg.state} #{@dbg.info}"
    draw_string_color(:status, w_w-str.length*@font_width-1, y, str)
    draw_string_color(:status, 1+@font_width, y, @statusline)
    y -= @font_height

    w_w_c = w_w/@font_width
    @caret_y = y
    if @caret_x < w_w_c-1
      render[':' + @curline, :curline]
    else
      render['~' + @curline[@caret_x-w_w_c+2, w_w_c], :curline]
    end

    l_nr = -1
    lastline = nil
    @log_offset = 0 if @log_offset < 0
    @log.reverse.each { |l|
      l.scan(/.{1,#{w_w/@font_width}}/).reverse_each { |l_|
        lastline = l_
        l_nr += 1
        next if l_nr < @log_offset
        render[l_, :log]
      }
      break if y < 0
    }
    if lastline and l_nr < @log_offset
      render[lastline, :log]
      @log_offset = l_nr-1
    end

    if focus?
      cx = [@caret_x+1, w_w_c-1].min*@font_width+1
      cy = @caret_y
      draw_line_color(:caret, cx, cy, cx, cy+@font_height-1)
    end

    @oldcaret_x = @caret_x
  end

  def keypress(key)
    case key
    when :left
      if @caret_x > 0
        @caret_x -= 1
        update_caret
      end
    when :right
      if @caret_x < @curline.length
        @caret_x += 1
        update_caret
      end
    when :up
      if not @cmd_histptr
        if @curline != ''
          @cmd_history << @curline
          @cmd_histptr = 2
        else
          @cmd_histptr = 1
        end
      else
        @cmd_histptr += 1
        @cmd_histptr = 1 if @cmd_histptr > @cmd_history.length
      end
      @curline = @cmd_history[-@cmd_histptr].dup
      @caret_x = @curline.length
      update_status_cmd
      redraw

    when :down
      if not @cmd_histptr
        @cmd_history << @curline if @curline != ''
        @cmd_histptr = @cmd_history.length
      else
        @cmd_histptr -= 1
        @cmd_histptr = @cmd_history.length if @cmd_histptr < 1
      end
      @curline = @cmd_history[-@cmd_histptr].dup
      @caret_x = @curline.length
      update_status_cmd
      redraw

    when :home
      @caret_x = 0
      update_caret
    when :end
      @caret_x = @curline.length
      update_caret

    when :pgup
      @log_offset += height/@font_height - 3
      redraw
    when :pgdown
      @log_offset -= height/@font_height - 3
      redraw

    when :tab
      # autocomplete
      if @caret_x > 0 and not @curline[0, @caret_x].index(?\ ) and st = @curline[0, @caret_x] and not @commands[st]
        keys = @commands.keys.find_all { |k| k[0, st.length] == st }
        while st.length < keys.first.to_s.length and keys.all? { |k| k[0, st.length+1] == keys.first[0, st.length+1] }
          st << keys.first[st.length]
          @curline[@caret_x, 0] = st[-1, 1]
          @caret_x += 1
        end
        update_status_cmd
        redraw
      end

    when :enter
      @cmd_histptr = nil
      handle_command
      update_status_cmd
    when :esc
    when :delete
      if @caret_x < @curline.length
        @curline[@caret_x, 1] = ''
        update_status_cmd
        redraw
      end
    when :backspace
      if @caret_x > 0
        @caret_x -= 1
        @curline[@caret_x, 1] = ''
        update_status_cmd
        redraw
      end

    when :insert
      if keyboard_state(:shift)
        txt = clipboard_paste.to_s
        @curline[@caret_x, 0] = txt
        @caret_x += txt.length
        update_status_cmd
        redraw
      end

    when Symbol; return false	# avoid :shift cannot coerce to Int warning
    when ?\x20..?\x7e
      @curline[@caret_x, 0] = key.chr
      @caret_x += 1
      update_status_cmd
      redraw

    else return false
    end
    true
  end

  def keypress_ctrl(key)
    case key
    when ?v
      txt = clipboard_paste.to_s
      @curline[@caret_x, 0] = txt
      @caret_x += txt.length
      update_status_cmd
      redraw
    else return false
    end
    true
  end

  def update_status_cmd
    st = @curline.split.first
    if @commands[st]
      @statusline = "#{st}: #{@cmd_help[st]}"
    else
      keys = @commands.keys.find_all { |k| k[0, st.length] == st } if st
      if keys and not keys.empty?
        @statusline = keys.sort.join(' ')
      else
        @statusline = 'type \'help\' for help'
      end
    end
  end

  def new_command(*cmd, &b)
    hlp = cmd.pop if cmd.last.include? ' '
    cmd.each { |c|
      @cmd_help[c] = hlp || 'nodoc'
      @commands[c] = lambda { |*a| protect { b.call(*a) } }
    }
  end

  # arg str -> expr value, with special codeptr/dataptr = code/data.curaddr
  def parse_expr(arg)
    parse_expr!(arg.dup)
  end

  def parse_expr!(arg)
    @dbg.parse_expr!(arg) { |e|
      case e.downcase
      when 'code_addr', 'codeptr'; @parent_widget.code.curaddr
      when 'data_addr', 'dataptr'; @parent_widget.mem.curaddr
      end
    }
  end

  def solve_expr(arg)
    return arg if arg.kind_of? Integer
    solve_expr!(arg.dup)
  end

  def solve_expr!(arg)
    return if not e = parse_expr!(arg)
    @dbg.resolve_expr(e)
  end

  # update the data window, or dump data to console if len given
  def cmd_dd(addr, dlen=nil, len=nil)
    if addr.kind_of? String
      s = addr.strip
      addr = solve_expr!(s) || @parent_widget.mem.curaddr
      if not s.empty?
        s = s[1..-1] if s[0] == ?,
        len ||= solve_expr(s)
      end
    end

    if len
      while len > 0
        data = @dbg.memory[addr, [len, 16].min]
        le = (@dbg.cpu.endianness == :little)
        data = '' if @dbg.memory.page_invalid?(addr)
        case dlen
        when nil; add_log "#{Expression[addr]}  #{data.unpack('C*').map { |c| '%02X' % c }.join(' ').ljust(2*16+15)}  #{data.tr("^\x20-\x7e", '.')}"
        when 1;   add_log "#{Expression[addr]}  #{data.unpack('C*').map { |c| '%02X' % c }.join(' ')}"
        when 2;   add_log "#{Expression[addr]}  #{data.unpack(le ? 'v*' : 'n*').map { |c| '%04X' % c }.join(' ')}"
        when 4;   add_log "#{Expression[addr]}  #{data.unpack(le ? 'V*' : 'N*').map { |c| '%08X' % c }.join(' ')}"
        when 8;   add_log "#{Expression[addr]}  #{data.unpack('Q*').map { |c| '%016X' % c }.join(' ')}"
        end
        addr += 16
        len -= 16
      end
    else
      if dlen
        @parent_widget.mem.view(:hex).data_size = dlen
        @parent_widget.mem.view(:hex).resized
        @parent_widget.mem.showview(:hex)
      end
      @parent_widget.mem.focus_addr(solve_expr(addr))
      @parent_widget.mem.gui_update
    end
  end

  def init_commands
    @commands = {}
    @cmd_help = {}
    p = @parent_widget
    new_command('help') { add_log @commands.keys.sort.join(' ') } # TODO help <subject>
    new_command('d', 'focus data window on an address') { |arg| cmd_dd(arg) }
    new_command('db', 'dump/focus bytes in data window')  { |arg| cmd_dd(arg, 1) }
    new_command('dw', 'dump/focus words in data window')  { |arg| cmd_dd(arg, 2) }
    new_command('dd', 'dump/focus dwords in data window') { |arg| cmd_dd(arg, 4) }
    new_command('dq', 'dump/focus qwords in data window') { |arg| cmd_dd(arg, 8) }
    new_command('dc', 'focus C struct in data window: <name> <addr>') { |arg|
      name, addr = arg.strip.split(/\s+/, 2)
      addr = (addr ? solve_expr(addr) : @parent_widget.mem.curaddr)
      @parent_widget.mem.focus_addr(addr, :cstruct, false, name)
    }
    new_command('dC', 'dump C struct: dC <name> <addr>') { |arg|
      name, addr = arg.strip.split(/\s+/, 2)
      addr = (addr ? solve_expr(addr) : @parent_widget.mem.curaddr)
      if st = @dbg.disassembler.c_parser.decode_c_struct(name, @dbg.memory, addr)
        add_log st.to_s.gsub("\t", '  ')
      end
    }
    new_command('u', 'focus code window on an address') { |arg| p.code.focus_addr(solve_expr(arg)) }
    new_command('.', 'focus code window on current address') { p.code.focus_addr(solve_expr(@dbg.register_pc.to_s)) }
    new_command('wc', 'set code window height') { |arg|
      if arg == ''
        p.code.curview.grab_focus
      else
        p.resize_child(p.code, width, arg.to_i*@font_height)
      end
    }
    new_command('wd', 'set data window height') { |arg|
      if arg == ''
        p.mem.curview.grab_focus
      else
        p.resize_child(p.mem, width, arg.to_i*@font_height)
      end
    }
    new_command('wp', 'set console window height') { |arg|
      if arg == ''
        grab_focus
      else
        p.resize_child(self, width, arg.to_i*@font_height)
      end
    }
    new_command('width', 'set window width (chars)') { |arg|
      if a = solve_expr(arg); p.win.width = a*@font_width
      else add_log "width #{p.win.width/@font_width}"
      end
    }
    new_command('height', 'set window height (chars)') { |arg|
      if a = solve_expr(arg); p.win.height = a*@font_height
      else add_log "height #{p.win.height/@font_height}"
      end
    }
    new_command('continue', 'run', 'let the target run until something occurs') { p.dbg_continue }
    new_command('stepinto', 'singlestep', 'run a single instruction of the target') { p.dbg_singlestep }
    new_command('stepover', 'run a single instruction of the target, do not enter into subfunctions') { p.dbg_stepover }
    new_command('stepout', 'stepover until getting out of the current function') { p.dbg_stepout }
    new_command('bpx', 'set a breakpoint') { |arg|
      arg =~ /^(.*?)( once)?(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
      e, o, c, a = $1, $2, ($3 || $5), $4
      o = o ? true : false
      cd = parse_expr(c) if c
      cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
      @dbg.bpx(solve_expr(e), o, cd, &cb)
    }
    new_command('hwbp', 'set a hardware breakpoint (hwbp 0x2345 w)') { |arg|
      arg =~ /^(.*?)( once)?( [rwx])?(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
      e, o, t, c, a = $1, $2, $3, ($4 || $6), $5
      o = o ? true : false
      t = (t || 'x').strip.to_sym
      cd = parse_expr(c) if c
      cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
      @dbg.hwbp(solve_expr(e), t, 1, o, cd, &cb)
    }
    new_command('bpm', 'set a hardware memory breakpoint: bpm r 0x4800ff 16') { |arg|
      arg =~ /^(.*?)(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
      e, c, a = $1, ($2 || $4), $3
      cd = parse_expr(c) if c
      cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
      raise 'bad syntax: bpm r|w|x addr [len]' unless e =~ /^([rwx]) (.*)/i
      mode = $1.downcase.to_sym
      e = $2
      exp = solve_expr!(e)
      len = solve_expr(e) if e != ''
      len ||= 1
      @dbg.bpm(exp, mode, len, false, cd, &cb)
    }
    new_command('g', 'wait until target reaches the specified address') { |arg|
      arg =~ /^(.*?)(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
      e, c, a = $1, ($2 || $4), $3
      cd = parse_expr(c) if c
      cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
      @dbg.bpx(solve_expr(e), true, cd, &cb) if arg
      p.dbg_continue
    }
    new_command('refresh', 'redraw', 'update', 'update the target memory/register cache') {
      @dbg.invalidate
      @dbg.dasm_invalidate
      p.gui_update
    }
    new_command('bl', 'list breakpoints') {
      @bl = []
      @dbg.all_breakpoints.each { |b|
        add_log "#{@bl.length} #{@dbg.addrname!(b.address)} #{b.type} #{b.state}#{" if #{b.condition}" if b.condition}"
        @bl << b
      }
    }
    new_command('bc', 'clear breakpoints') { |arg|
      @bl ||= @dbg.all_breakpoints
      if arg == '*'
        @bl.each { |b| @dbg.del_bp(b) }
      else
        next if not i = solve_expr(arg)
        if b = @bl[i]
          @dbg.del_bp(b)
        end
      end
    }
    new_command('break', 'interrupt a running target') { |arg| @dbg.break ; p.post_dbg_run }
    new_command('kill', 'kill the target') { |arg| @dbg.kill(arg) ; p.post_dbg_run }
    new_command('detach', 'detach from the target') { @dbg.detach ; p.post_dbg_run }
    new_command('r', 'read/write the content of a register') { |arg|
      reg, val = arg.split(/\s+|\s*=\s*/, 2)
      if reg == 'fl'
        @dbg.toggle_flag(val.to_sym)
      elsif not reg
        @dbg.register_list.each { |r|
          add_log "#{r} = #{Expression[@dbg.get_reg_value(r)]}"
        }
      elsif not val
        add_log "#{reg} = #{Expression[@dbg.get_reg_value(reg.to_sym)]}"
      else
        @dbg.set_reg_value(reg.to_sym, solve_expr(val))
      end
      p.regs.gui_update
    }
    new_command('ma', 'memory_ascii', 'write memory (ascii) - ma <addr> foo bar') { |arg|
      next if not addr = solve_expr!(arg)
      data = arg.strip
      @dbg.memory[addr, data.length] = data
      @dbg.invalidate
      @dbg.dasm_invalidate
      p.gui_update
    }
    new_command('mx', 'memory_hex', 'write memory (hex) - mx <addr> 0011223344') { |arg|
      next if not addr = solve_expr!(arg)
      data = [arg.delete(' ')].pack('H*')
      @dbg.memory[addr, data.length] = data
      @dbg.invalidate
      @dbg.dasm_invalidate
      p.gui_update
    }
    new_command('?', 'display a value') { |arg|
      next if not v = solve_expr(arg)
      add_log "#{v} 0x#{v.to_s(16)} #{[v & 0xffff_ffff].pack('L').inspect} #{@dbg.addrname!(v)}"
    }
    new_command('exit', 'quit', 'quit the debugger interface') { p.win.destroy }
    new_command('ruby', 'execute arbitrary ruby code') { |arg|
      case ret = eval(arg)
      when nil, true, false, Symbol; add_log ret.inspect
      when String; add_log ret[0, 64].inspect
      when Integer, Expression; add_log Expression[ret].to_s
      else add_log "#<#{ret.class}>"
      end
    }
    new_command('loadsyms', 'load symbols from a mapped module') { |arg|
      if not arg.empty? and arg = (solve_expr(arg) rescue arg)
        @dbg.loadsyms(arg)
      else
        @dbg.loadallsyms { |a|
          @statusline = "loading symbols from #{Expression[a]}"
          redraw
          Gui.main_iter
        }
      end
      p.gui_update
    }
    new_command('scansyms', 'scan target memory for loaded modules') {
      if defined? @scan_addr and @scan_addr
        add_log 'scanning @%08x' % @scan_addr
        next
      end
      @scan_addr = 0
      Gui.idle_add {
        if @scan_addr <= 0xffff_f000	# cpu.size?
          protect { @dbg.loadsyms(@scan_addr) }
          @scan_addr += 0x1000
          true
        else
          add_log 'scansyms finished'
          @scan_addr = nil
          p.gui_update
          nil
        end
      }
    }
    new_command('symbol', 'display information on symbols') { |arg|
      arg = arg.to_s.downcase
      @dbg.symbols.map { |k, v| an = @dbg.addrname(k) ; [k, an] if an.downcase.include? arg }.compact.sort_by { |k, v| v.downcase }.each { |k, v|
        add_log "#{Expression[k]} #{@dbg.addrname(k)}"
      }
    }
    new_command('maps', 'show file mappings from parsed modules') { |arg|
      want = arg.to_s.downcase
      want = nil if want == ''
      @dbg.modulemap.map { |n, (a_b, a_e)|
        [a_b, "#{Expression[a_b]}-#{Expression[a_e]} #{n}"] if not want or n.downcase.include?(want)
      }.compact.sort.each { |s1, s2|
        add_log s2
      }
    }
    new_command('rawmaps', 'show OS file mappings') { |arg|
      # XXX listwindow
      @dbg.mappings.sort.each { |a, l, *i|
        foo = i*' '
        next if arg.to_s != '' and foo !~ /#{arg}/i
        add_log "%08x %06x %s" % [a, l, i*' ']
      }
    }
    new_command('add_symbol', 'add a symbol name') { |arg|
      name, val = arg.to_s.split(/\s+/, 2)
      val = solve_expr(val)
      if val.kind_of? Integer
        @dbg.symbols[val] = name
        @dbg.disassembler.set_label_at(val, name)
        p.gui_update
      end
    }
    new_command('bt', 'backtrace', 'stacktrace', 'bt [limit] - show a stack trace from current pc') { |arg|
      arg = solve_expr(arg) if arg
      arg = 500 if not arg.kind_of? ::Integer
      @dbg.stacktrace(arg) { |a, s| add_log "#{Expression[a]} #{s}" }
    }
    new_command('dasm', 'disassemble_fast', 'disassembles from an address') { |arg|
      addr = solve_expr(arg)
      dasm = @dbg.disassembler
      dasm.disassemble_fast(addr)
      dasm.function_blocks(addr).keys.sort.each { |a|
        next if not di = dasm.di_at(a)
        dasm.dump_block(di.block) { |l| add_log l }
      }
      p.gui_update
    }
    new_command('save_hist', 'save the command buffer to a file') { |arg|
      File.open(arg, 'w') { |fd| fd.puts @log }
    }

    new_command('watch', 'follow an expression in the data view (none to delete)') { |arg|
      if not arg
        add_log p.watchpoint[p.mem].to_s
      elsif arg == 'nil' or arg == 'none' or arg == 'delete'
        p.watchpoint.delete p.mem
      else
        p.watchpoint[p.mem] = parse_expr(arg)
      end
    }

    new_command('list_pid', 'list pids currently debugged') { |arg|
      add_log @dbg.list_debug_pids.sort.map { |pp| pp == @dbg.pid ? "*#{pp}" : pp }.join(' ')
    }
    new_command('list_tid', 'list tids currently debugged') { |arg|
      add_log @dbg.list_debug_tids.sort.map { |tt| tt == @dbg.tid ? "*#{tt}" : tt }.join(' ')
    }

    new_command('list_processes', 'list processes available for debugging') { |arg|
      @dbg.list_processes.each { |pp|
        add_log "#{pp.pid} #{pp.path}"
      }
    }
    new_command('list_threads', 'list thread ids of the current process') { |arg|
      @dbg.list_threads.each { |t|
        stf = { :state => @dbg.state, :info => @dbg.info } if t == @dbg.tid
        stf ||= @dbg.tid_stuff[t]
        stf ||= {}
        add_log "#{t} #{stf[:state]} #{stf[:info]}"
      }
    }

    new_command('pid', 'select a pid') { |arg|
      if pid = solve_expr(arg)
        @dbg.pid = pid
      else
        add_log "pid #{@dbg.pid}"
      end
    }
    new_command('tid', 'select a tid') { |arg|
      if tid = solve_expr(arg)
        @dbg.tid = tid
      else
        add_log "tid #{@dbg.tid} #{@dbg.state} #{@dbg.info}"
      end
    }

    new_command('exception_pass', 'pass the exception unhandled to the target on next continue') {
      @dbg.pass_current_exception
    }
    new_command('exception_handle', 'handle the exception, hide it from the target on next continue') {
      @dbg.pass_current_exception false
    }

    new_command('exception_pass_all', 'ignore all target exceptions') {
      @dbg.pass_all_exceptions = true
    }
    new_command('exception_handle_all', 'break on target exceptions') {
      @dbg.pass_all_exceptions = false
    }

    new_command('thread_events_break', 'break on thread creation/termination') {
      @dbg.ignore_newthread = false
      @dbg.ignore_endthread = false
    }
    new_command('thread_events_ignore', 'ignore thread creation/termination') {
      @dbg.ignore_newthread = true
      @dbg.ignore_endthread = true
    }

    new_command('trace_children', 'trace children of debuggee (0|1)') { |arg|
      arg = case arg.to_s.strip.downcase
      when '0', 'no', 'false'; false
      else true
      end
      add_log "trace children #{arg ? 'active' : 'inactive'}"
      # update the flag for future debugee
      @dbg.trace_children = arg
      # change current debugee setting if supported
      @dbg.do_trace_children if @dbg.respond_to?(:do_trace_children)
    }

    new_command('attach', 'attach to a running process') { |arg|
      if pr = @dbg.list_processes.find { |pp| pp.path.to_s.downcase.include?(arg.downcase) }
        pid = pr.pid
      else
        pid = solve_expr(arg)
      end
      @dbg.attach(pid)
    }
    new_command('create_process', 'create a new process and debug it') { |arg|
      @dbg.create_process(arg)
    }

    new_command('plugin', 'load', 'load a debugger plugin') { |arg|
      @dbg.load_plugin arg
      add_log "loaded plugin #{File.basename(arg, '.rb')}"
    }


    @dbg.ui_command_setup(self) if @dbg.respond_to? :ui_command_setup
  end

  def wrap_run(&b) @parent_widget.wrap_run(&b) end
  def keyboard_callback; @parent_widget.keyboard_callback end
  def keyboard_callback_ctrl; @parent_widget.keyboard_callback_ctrl end

  def handle_command
    add_log(":#@curline")
    return if @curline == ''
    @cmd_history << @curline
    @cmd_history.shift if @cmd_history.length > @cmd_history_length
    @log_offset = 0
    cmd = @curline
    @curline = ''
    @caret_x = 0

    run_command(cmd)
  end

  def run_command(cmd)
    cmd = cmd.sub(/^\s+/, '')
    cn = cmd.split.first
    if not @commands[cn]
      a = @commands.keys.find_all { |k| k[0, cn.length] == cn }
      cn = a.first if a.length == 1
    end
    if pc = @commands[cn]
      pc[cmd.split(/\s+/, 2)[1].to_s]
    else
      add_log 'unknown command'
    end
  end

  def add_log(l)
    @log << l.to_s
    @log.shift if log.length > @log_length
    redraw
  end

  def gui_update
    redraw
  end

  # hint that the caret moved
  def update_caret
    return if @oldcaret_x == @caret_x
    w_w = width - @font_width
    x1 = (@oldcaret_x+1) * @font_width + 1
    x2 = (@caret_x+1) * @font_width + 1
    y = @caret_y

    if x1 > w_w or x2 > w_w
      invalidate(0, y, 100000, @font_height)
    else
      invalidate(x1-1, y, 2, @font_height)
      invalidate(x2-1, y, 2, @font_height)
    end

    @oldcaret_x = @caret_x
  end
end

class DbgWindow < Window
  attr_accessor :dbg_widget
  def initialize_window(dbg = nil, title='metasm debugger')
    self.title = title
    display(dbg) if dbg
  end

  # show a new DbgWidget
  def display(dbg)
    @dbg_widget = DbgWidget.new(dbg)
    @dbg_widget.win = self
    self.widget = @dbg_widget
    @dbg_widget
  end

  def build_menu
    filemenu = new_menu
    addsubmenu(filemenu, '_attach process') { @dbg_widget.prompt_attach }
    addsubmenu(filemenu, 'create _process') { @dbg_widget.prompt_createprocess }
    addsubmenu(filemenu, 'open _dasm window') { DasmWindow.new }
    addsubmenu(filemenu)
    addsubmenu(filemenu, 'QUIT') { destroy }

    addsubmenu(@menu, filemenu, '_File')

    dbgmenu = new_menu
    addsubmenu(dbgmenu, 'continue', '<f5>') { @dbg_widget.dbg_continue }
    addsubmenu(dbgmenu, 'step over', '<f10>') { @dbg_widget.dbg_stepover }
    addsubmenu(dbgmenu, 'step into', '<f11>') { @dbg_widget.dbg_singlestep }
    addsubmenu(dbgmenu, '_kill target') { @dbg_widget.dbg.kill }
    addsubmenu(dbgmenu, '_detach target') { @dbg_widget.dbg.detach }
    addsubmenu(dbgmenu)
    addsubmenu(dbgmenu, 'QUIT') { destroy }

    addsubmenu(@menu, dbgmenu, '_Debug')

    codeviewmenu = new_menu
    addsubmenu(codeviewmenu, '_listing') { @dbg_widget.code.focus_addr(@dbg_widget.code.curaddr, :listing) }
    addsubmenu(codeviewmenu, '_graph') { @dbg_widget.code.focus_addr(@dbg_widget.code.curaddr, :graph) }
    addsubmenu(codeviewmenu, 'raw _opcodes') { @dbg_widget.code.focus_addr(@dbg_widget.code.curaddr, :opcodes) }

    dataviewmenu = new_menu
    addsubmenu(dataviewmenu, '_hexa') { @dbg_widget.mem.focus_addr(@dbg_widget.mem.curaddr, :hex) }
    addsubmenu(dataviewmenu, 'raw _opcodes') { @dbg_widget.mem.focus_addr(@dbg_widget.mem.curaddr, :opcodes) }
    addsubmenu(dataviewmenu, '_c struct') { @dbg_widget.mem.focus_addr(@dbg_widget.mem.curaddr, :cstruct) }

    focusmenu = new_menu
    addsubmenu(focusmenu, '_regs') { @dbg_widget.regs.grab_focus ; @dbg_widget.redraw }
    addsubmenu(focusmenu, '_data') { @dbg_widget.mem.grab_focus ; @dbg_widget.redraw }
    addsubmenu(focusmenu, '_code') { @dbg_widget.code.grab_focus ; @dbg_widget.redraw }
    addsubmenu(focusmenu, 'conso_le', '.') { @dbg_widget.console.grab_focus ; @dbg_widget.redraw }

    viewmenu = new_menu
    addsubmenu(viewmenu, codeviewmenu, '_code display')
    addsubmenu(viewmenu, dataviewmenu, '_data display')
    addsubmenu(viewmenu, focusmenu, '_focus')
    addsubmenu(viewmenu, 'data _watch') { @dbg_widget.prompt_datawatch }
    addsubmenu(@menu, viewmenu, '_Views')
  end
end

end
end
