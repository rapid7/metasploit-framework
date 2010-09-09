#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

require 'metasm/gui/dasm_main'

module Metasm
module Gui

# TODO invalidate dbg.disassembler on selfmodifying code
# TODO handle multiple threads, reattach, etc
# TODO customize child widgets (listing: persistent hilight of current instr, show/set breakpoints, ...)
# TODO handle debugee fork()
class DbgWidget < ContainerVBoxWidget
	attr_accessor :dbg, :console, :regs, :code, :mem, :win
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
				'f88'
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

		@code.focus_addr(@dbg.resolve_expr(@watchpoint[@code]), :graph)
		@mem.focus_addr(0, :hex)
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
		return @parent_widget ? @parent_widget.keypress_ctrl(key) : false
	end

	def pre_dbg_run
		@regs.pre_dbg_run
	end

	def post_dbg_run
		want_redraw = true
		return if @idle_checking ||= nil	# load only one bg proc
		@idle_checking = true
		Gui.idle_add {
			@dbg.check_target
			if @dbg.state == :running
				redraw if want_redraw	# redraw once if the target is running (less flicker with singlestep)
				want_redraw = false
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
	end

	def wrap_run
		pre_dbg_run
		yield
		post_dbg_run
	end

	def dbg_continue(*a) wrap_run { @dbg.continue(*a) } end
	def dbg_singlestep(*a) wrap_run { @dbg.singlestep(*a) } end
	def dbg_stepover(*a) wrap_run { @dbg.stepover(*a) } end
	def dbg_stepout(*a) wrap_run { @dbg.stepout(*a) } end	# TODO idle_add etc

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
		@write_pending = {}	# addr -> newvalue (bytewise)

		@registers = @dbg.register_list
		@flags = @dbg.flag_list
		@register_size = Hash.new(1) ; @registers.each { |r| @register_size[r] = @dbg.register_size[r]/4 }
		@reg_cache = Hash.new(0)
		@reg_cache_old = {}
		@reg_pos = []	# list of x y w h vx of the reg drawing on widget, vx is x of value
	
		@default_color_association = { :label => :black, :data => :blue, :write_pending => :darkred,
				       	:changed => :darkgreen, :caret => :black, :background => :white,
					:inactive => :palegrey }
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
		curaddr = 0
		x = 1
		y = 0

		w_w = width

		render = lambda { |str, color|
			draw_string_color(color, x, y, str)
			x += str.length * @font_width
		}

		@reg_pos = []
		running = (@dbg.state != :stopped)
		@registers.each { |reg|
			strlen = reg.to_s.length + 1 + @register_size[reg]
			if x + strlen*@font_width >= w_w
				x = 1
				y += @font_height
			end
			@reg_pos << [x, y, (strlen+1)*@font_width, @font_height, x+(reg.to_s.length+1)*@font_width]

			render["#{reg}=", :label]
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
		@reg_cache_old = @reg_cache.dup if @reg_cache
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
		@reg_cache = @registers.inject({}) { |h, r| h.update r => @dbg.get_reg_value(r) }
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

		@default_color_association = { :log => :palegrey, :curline => :white, :caret => :yellow,
			:background => :black, :status => :black, :status_bg => '088' }

		init_commands
	end

	def initialize_visible
		grab_focus
		gui_update
	end

	def click(x, y)
		@caret_x = (x-1).to_i / @font_width - 1
		@caret_x = [[@caret_x, 0].max, @curline.length].min
		update_caret
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
		str = "#{@dbg.state} #{@dbg.info}"
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
		@dbg.parse_expr(arg) { |e|
			case e.downcase
			when 'code_addr', 'codeptr'; @parent_widget.code.curaddr
			when 'data_addr', 'dataptr'; @parent_widget.mem.curaddr
			end
		}
	end

	def solve_expr(arg)
		return if not e = parse_expr(arg)
		@dbg.resolve_expr(e)
	end

	def init_commands
		@commands = {}
		@cmd_help = {}
		p = @parent_widget
		dasm = @dbg.disassembler
		new_command('help') { add_log @commands.keys.sort.join(' ') } # TODO help <subject>
		new_command('d', 'focus data window on an address') { |arg| p.mem.focus_addr(solve_expr(arg)) }
		new_command('db', 'display bytes in data window') { |arg| p.mem.curview.data_size = 1 ; p.mem.gui_update ; @commands['d'][arg] }
		new_command('dw', 'display bytes in data window') { |arg| p.mem.curview.data_size = 2 ; p.mem.gui_update ; @commands['d'][arg] }
		new_command('dd', 'display bytes in data window') { |arg| p.mem.curview.data_size = 4 ; p.mem.gui_update ; @commands['d'][arg] }
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
		new_command('continue', 'run', 'let the target run until something occurs') { |arg| p.dbg_continue(arg) }
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
		new_command('hwbp', 'set a hardware breakpoint') { |arg|
			arg =~ /^(.*?)(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
			e, c, a = $1, ($2 || $4), $3
			cd = parse_expr(c) if c
			cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
			@dbg.hwbp(solve_expr(e), :x, 1, false, cd, &cb)
		}
		new_command('bpm', 'set a hardware memory breakpoint: bpm r 0x4800ff 16') { |arg|
			arg =~ /^(.*?)(?: if (.*?))?(?: do (.*?))?(?: if (.*?))?$/i
			e, c, a = $1, ($2 || $4), $3
			cd = parse_expr(c) if c
			cb = lambda { a.split(';').each { |aaa| run_command(aaa) } } if a
			raise 'bad syntax: bpm r|w|x addr [len]' unless e =~ /^([rwx]) (.*)/i
			mode = $1.downcase.to_sym
			e = $2
			exp = solve_expr(e)
			len = solve_expr(e) if e != ''
			len ||= 1
			@dbg.hwbp(exp, mode, len, false, cd, &cb)
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
			i = -1
			@dbg.breakpoint.sort.each { |a, b|
				add_log "#{i+=1} #{Expression[a]} #{b.type} #{b.state}#{" if #{b.condition}" if b.condition}#{' do {}' if b.action}"
			}
		}
		new_command('bc', 'clear breakpoints') { |arg|
			if arg == '*'
				@dbg.breakpoint.keys.each { |i| @dbg.remove_breakpoint(i) }
			else
				next if not i = solve_expr(arg)
				i = @dbg.breakpoint.sort[i][0] if i < @dbg.breakpoint.length
				@dbg.remove_breakpoint(i)
			end
		}
		new_command('break', 'interrupt a running target') { |arg| @dbg.break ; p.post_dbg_run }
		new_command('kill', 'kill the target') { |arg| @dbg.kill(arg) ; p.post_dbg_run }
		new_command('detach', 'detach from the target') { @dbg.detach ; p.post_dbg_run }
		new_command('r', 'read/write the content of a register') { |arg|
			reg, val = arg.split(/\s+/, 2)
			if reg == 'fl'
				@dbg.toggle_flag(val.to_sym)
			elsif not val
				add_log "#{reg} = #{Expression[@dbg.get_reg_value(reg.to_sym)]}"
			else
				@dbg.set_reg_value(reg.to_sym, solve_expr(val))
			end
			p.regs.gui_update
		}
		new_command('m', 'memory_dump', 'dump memory - m <addr> <len>') { |arg|
			next if not addr = solve_expr(arg)
			len = solve_expr(arg) || 16
			mem = @dbg.memory[addr, len]
			mem.scan(/.{1,16}/m).each { |l|
				hex = l.unpack('C*').map { |c| '%02x' % c }.join(' ')
				asc = l.gsub(/[^0x20-0x7e]/, '.')
				add_log "#{Expression[addr]} #{hex.ljust(3*16)} #{asc}"
				addr += l.length
			}
		}
		new_command('ma', 'memory_ascii', 'write memory (ascii) - ma <addr> foo bar') { |arg|
			next if not addr = solve_expr(arg)
			data = arg.strip
			@dbg.memory[addr, data.length] = data
			@dbg.invalidate
			@dbg.dasm_invalidate
			p.gui_update
		}
		new_command('mx', 'memory_hex', 'write memory (hex) - mx <addr> 0011223344') { |arg|
			next if not addr = solve_expr(arg)
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
			if not arg.empty? and arg = (solve_expr(arg.dup) rescue arg)
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
			@dbg.symbols.map { |k, v| [k, @dbg.addrname(k)] if v.downcase.include? arg }.compact.sort_by { |k, v| v.downcase }.each { |k, v|
				add_log "#{Expression[k]} #{@dbg.addrname(k)}"
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
			dasm.disassemble_fast(addr)
			dasm.each_function_block(addr).sort.each { |a|
				next if not di = dasm.di_at(a)
				dasm.dump_block(di.block) { |l| add_log l }
			}
			p.gui_update
		}
		new_command('save_hist', 'save the command buffer to a file') { |arg|
			File.open(arg, 'w') { |fd| fd.puts @log }
		}
		# TODO 'macro', 'map', 'thread'

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
		dbgmenu = new_menu
		addsubmenu(dbgmenu, 'continue', '<f5>') { @dbg_widget.dbg_continue }
		addsubmenu(dbgmenu, 'step over', '<f10>') { @dbg_widget.dbg_stepover }
		addsubmenu(dbgmenu, 'step into', '<f11>') { @dbg_widget.dbg_singlestep }
		addsubmenu(dbgmenu, 'kill target') { @dbg_widget.dbg.kill }	# destroy ?
		addsubmenu(dbgmenu, 'detach target') { @dbg_widget.dbg.detach }	# destroy ?
		addsubmenu(dbgmenu)
		addsubmenu(dbgmenu, 'QUIT') { destroy }

		addsubmenu(@menu, dbgmenu, '_Actions')
	end
end

end
end
