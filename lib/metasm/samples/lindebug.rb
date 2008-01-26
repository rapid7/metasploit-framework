#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

# 
# this is a linux/x86 debugger with a console interface
#

require 'metasm'

module Ansi
	CursHome = "\e[H".freeze
	ClearLineAfter  = "\e[0K"
	ClearLineBefore = "\e[1K"
	ClearLine = "\e[2K"
	ClearScreen = "\e[2J"
	def self.set_cursor_pos(y=1,x=1) "\e[#{y};#{x}H" end
	Reset = "\e[m"
	Colors = [:black, :red, :green, :yellow, :blue, :magenta, :cyan, :white, :aoeu, :reset]
	def self.color(*args)
		fg = true
		"\e[" << args.map { |a|
			case a
			when :bold: 2
			when :negative: 7
			when :normal: 22
			when :positive: 27
			else
				if col = Colors.index(a)
					add = (fg ? 30 : 40)
					fg = false
					col+add
				end
			end
		}.compact.join(';') << 'm'
	end
	def self.hline(len) "\e(0"<<'q'*len<<"\e(B" end

	TIOCGWINSZ = 0x5413
	TCGETS = 0x5401
	TCSETS = 0x5402
	CANON = 2
	ECHO  = 8
	def self.get_terminal_size
		s = ''.ljust(8)
		$stdin.ioctl(TIOCGWINSZ, s) >= 0 ? s.unpack('SS') : [80, 25]
	end
	def self.set_term_canon(bool)
		tty = ''.ljust(256)
		$stdin.ioctl(TCGETS, tty)
		if bool
			tty[12] &= ~(ECHO|CANON)
		else
			tty[12] |= ECHO|CANON
		end
		$stdin.ioctl(TCSETS, tty)
	end

	ESC_SEQ = {'A' => :up, 'B' => :down, 'C' => :right, 'D' => :left,
		'1~' => :home, '2~' => :inser, '3~' => :suppr, '4~' => :end,
		'5~' => :pgup, '6~' => :pgdown,
		'P' => :f1, 'Q' => :f2, 'R' => :f3, 'S' => :f4,
		'15~' => :f5, '17~' => :f6, '18~' => :f7, '19~' => :f8,
		'20~' => :f9, '21~' => :f10, '23~' => :f11, '24~' => :f12,
		'[A' => :f1, '[B' => :f2, '[C' => :f3, '[D' => :f4, '[E' => :f5,
		'H' => :home, 'F' => :end,
	}
	def self.getkey
		c = $stdin.getc
		return c if c != ?\e
		c = $stdin.getc
		if c != ?[ and c != ?O
			$stdin.ungetc c
			return ?\e
		end
		seq = ''
		loop do
			c = $stdin.getc
			seq << c
			case c; when ?a..?z, ?A..?Z, ?~: break end
		end
		ESC_SEQ[seq] || seq
	end
end

class Indirect
	attr_accessor :ptr, :sz
	UNPACK_STR = {1 => 'C', 2 => 'S', 4 => 'L'}
	def initialize(ptr, sz) @ptr, @sz = ptr, sz end
	def bind(bd)
		raw = bd['tracer_memory'][@ptr.bind(bd).reduce, @sz]
		Metasm::Expression[raw.unpack(UNPACK_STR[@sz]).first]
	end
end

class ExprParser < Metasm::Expression
	def self.parse_intfloat(lex, tok)
		case tok.raw
		when 'byte', 'word', 'dword'
			nil while ntok = lex.readtok and ntok.type == :space
			nil while ntok = lex.readtok and ntok.type == :space if ntok and ntok.raw == 'ptr'
			if ntok and ntok.raw == '['
				tok.value = Indirect.new(parse(lex), {'byte' => 1, 'word' => 2, 'dword' => 4}[tok.raw])
				nil while ntok = lex.readtok and ntok.type == :space
				nil while ntok = lex.readtok and ntok.type == :space if ntok and ntok.raw == ']'
				lex.unreadtok ntok
			end
		else super
		end
	end
	def self.parse_value(lex)
		nil while tok = lex.readtok and tok.type == :space
		lex.unreadtok tok
		if tok and tok.type == :punct and tok.raw == '['
			tt = tok.dup
			tt.type = :string
			tt.raw = 'dword'
			lex.unreadtok tt
		end
		super
	end
end

class LinDebug
	attr_accessor :win_data_height, :win_code_height, :win_prpt_height
	def init_screen
		Ansi.set_term_canon(true)
		@win_data_height = 20
		@win_code_height = 20
		resize
	end

	def fini_screen
		Ansi.set_term_canon(false)
	end

	def win_data_start; 2 end
	def win_code_start; win_data_start+win_data_height end
	def win_prpt_start; win_code_start+win_code_height end

	Color = {:changed => Ansi.color(:cyan, :bold), :border => Ansi.color(:green),
		:normal => Ansi.color(:white, :black, :normal), :hilight => Ansi.color(:blue, :white, :normal),
		:status => Ansi.color(:black, :cyan)}

	attr_accessor :dataptr, :codeptr, :rs, :promptlog
	def initialize(rs)
		@rs = rs
		@rs.logger = self
		@dataptr = 0
		@datafmt = 'db'

		@prompthistlen = 20
		@prompthistory = []
		@promptloglen = 200
		@promptlog = []
		@promptbuf = ''
		@promptpos = 0
		@log_off = 0

		@focus = :prompt
		@command = {}
		load_commands
		trap('WINCH') { resize }

		stack = @rs[@rs.regs_cache['esp'], 0x1000].unpack('L*')
		stack.shift	# argc
		stack.shift until stack.empty? or stack.first == 0	# argv
		stack.shift
		stack.shift until stack.empty? or stack.first == 0	# envp
		stack.shift
		stack.shift until stack.empty? or stack.shift == 3	# find PHDR ptr in auxv
		if phdr = stack.shift
			phdr &= 0xffff_f000
			@rs.loadsyms phdr, phdr.to_s(16)
		end
	end

	def main_loop
		begin
			begin
				init_screen
				main_loop_inner
			rescue Errno::ESRCH
				log "target does not exist anymore"
			ensure
				fini_screen
				$stdout.print Ansi.set_cursor_pos(@console_height, 1)
			end
		rescue
			$stdout.puts $!, $!.backtrace
		end
		$stdout.puts @promptlog.last
	end
	
	def update
		csy, csx = @console_height-1, @promptpos+2
		$stdout.write Ansi.set_cursor_pos(0, 0) + updateregs + updatedata + updatecode + updateprompt + Ansi.set_cursor_pos(csy, csx)
	end

	def updateregs
		text = ''
		text << ' '
		x = 1
		%w[eax ebx ecx edx eip].each { |r|
			text << Color[:changed] if @rs.regs_cache[r] != @rs.oldregs[r]
			text << r << ?=
			text << ('%08X' % @rs.regs_cache[r])
			text << Color[:normal] if @rs.regs_cache[r] != @rs.oldregs[r]
			text << '  '
			x += r.length + 11
		}
		text << (' '*(@console_width-x)) << "\n" << ' '
		x = 1
		%w[esi edi ebp esp].each { |r|
			text << Color[:changed] if @rs.regs_cache[r] != @rs.oldregs[r]
			text << r << ?=
			text << ('%08X' % @rs.regs_cache[r])
			text << Color[:normal] if @rs.regs_cache[r] != @rs.oldregs[r]
			text << '  '
			x += r.length + 11
		}
		Rubstop::EFLAGS.sort.each { |off, flag|
			val = @rs.regs_cache['eflags'] & (1<<off)
			flag = flag.upcase if val != 0
			if val != @rs.oldregs['eflags'] & (1 << off)
				text << Color[:changed]
				text << flag
				text << Color[:normal]
			else
				text << flag
			end
			text << ' '
			x += 2
		}
		text << (' '*(@console_width-x)) << "\n"
	end

	def updatecode
		if @codeptr
			addr = @codeptr
		elsif @rs.oldregs['eip'] and @rs.oldregs['eip'] < @rs.regs_cache['eip'] and @rs.oldregs['eip'] + 8 >= @rs.regs_cache['eip']
			addr = @rs.oldregs['eip']
		else
			addr = @rs.regs_cache['eip']
		end
		@codeptr = addr

		if @rs.findfilemap(addr) == '???'
			base = addr & 0xffff_f000
			8.times {
				sig = @rs[base, 4]
				if sig == "\x7fELF"
					@rs.loadsyms(base, base.to_s(16))
					break
				end
				base -= 0x1000
			}
		end

		text = ''
		text << Color[:border]
		title = @rs.findsymbol(addr)
		pre  = [@console_width-100, 6].max
		post = @console_width - (pre + title.length + 2)
		text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post)
		text << Color[:normal]
		text << "\n"

		cnt = @win_code_height
		while (cnt -= 1) > 0
			if @rs.symbols[addr]
				text << ('    ' << @rs.symbols[addr] << ?:) << Ansi::ClearLineAfter << "\n"
				break if (cnt -= 1) <= 0
			end
			text << Color[:hilight] if addr == @rs.regs_cache['eip']
			text << ('%04X' % @rs.regs_cache['cs']) << ':'
			text << ('%08X' % addr)
			di = @rs.mnemonic_di(addr)
			di = nil if di and addr < @rs.regs_cache['eip'] and addr+di.bin_length > @rs.regs_cache['eip']
			len = (di ? di.bin_length : 1)
			text << '  '
			text << @rs[addr, [len, 10].min].unpack('C*').map { |c| '%02X' % c }.join.ljust(22)
			if di
				text <<
				if addr == @rs.regs_cache['eip']
					"*#{di.instruction}".ljust(@console_width-37)
				else
					" #{di.instruction}" << Ansi::ClearLineAfter
				end
			else
				text << ' <unk>' << Ansi::ClearLineAfter
			end
			text << Color[:normal] if addr == @rs.regs_cache['eip']
			addr += len
			text << "\n"
		end
		text
	end

	def updatedata
		@dataptr &= 0xffff_ffff
		addr = @dataptr

		text = ''
		text << Color[:border]
		title = @rs.findsymbol(addr)
		pre  = [@console_width-100, 6].max
		post = @console_width - (pre + title.length + 2)
		text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post)
		text << Color[:normal]

		cnt = @win_data_height
		while (cnt -= 1) > 0
			raw = @rs[addr, 16]
			text << ('%04X' % @rs.regs_cache['ds']) << ':' << ('%08X' % addr) << '  '
			case @datafmt
			when 'db': text << raw[0,8].unpack('C*').map { |c| '%02x ' % c }.join << ' ' <<
				   raw[8,8].unpack('C*').map { |c| '%02x ' % c }.join
			when 'dw': text << raw.unpack('S*').map { |c| '%04x ' % c }.join
			when 'dd': text << raw.unpack('L*').map { |c| '%08x ' % c }.join
			end
			text << ' ' << raw.unpack('C*').map { |c| (0x20..0x7e).include?(c) ? c : ?. }.pack('C*')
			text << Ansi::ClearLineAfter << "\n"
			addr += 16
		end
		text
	end

	def updateprompt
		text = ''
		text << Color[:border] << Ansi.hline(@console_width) << Color[:normal] << "\n"

		@log_off = @promptlog.length - 2 if @log_off >= @promptlog.length
		@log_off = 0 if @log_off < 0
		len = @win_prpt_height - 2
		len.times { |i|
			i += @promptlog.length - @log_off - len
			text << ((@promptlog[i] if i >= 0) || '')
			text << Ansi::ClearLineAfter << "\n"
		}
		text << ':' << @promptbuf << Ansi::ClearLineAfter << "\n"
		text << Color[:status] << statusline.ljust(@console_width) << Color[:normal]
	end

	def statusline
		'    Enter a command (help for help)'
	end

	def resize
		@console_height, @console_width = Ansi.get_terminal_size
		@win_data_height = 1 if @win_data_height < 1
		@win_code_height = 1 if @win_code_height < 1
		if @win_data_height + @win_code_height + 5 > @console_height
			@win_data_height = @console_height/2 - 4
			@win_code_height = @console_height/2 - 4
		end
		@win_prpt_height = @console_height-(@win_data_height+@win_code_height+2) - 1
		update
	end

	def log(str)
		raise str.inspect if not str.kind_of? ::String
		@promptlog << str
		@promptlog.shift if @promptlog.length > @promptloglen
	end

	def puts(*s)
		s.each { |s| log s.to_s }
		update rescue nil
	end

	def mem_binding(expr)
		b = @rs.regs_cache.dup
		ext = expr.externals
		ext.map! { |exte| exte.kind_of?(Indirect) ? exte.ptr.externals : exte }.flatten! while not ext.grep(Indirect).empty?
		(ext - @rs.regs_cache.keys).each { |ex|
			if not s = @rs.symbols.index(ex)
				log "unknown value #{ex}"
				return {}
			end
			b[ex] = s
			if @rs.symbols.values.grep(ex).length > 1
				raise "multiple definitions found for #{ex}"
			end
		}
		b['tracer_memory'] = @rs
		b
	end

	def exec_prompt
		@log_off = 0
		log ':'+@promptbuf
		return if @promptbuf == ''
		lex = Metasm::Preprocessor.new.feed @promptbuf
		@prompthistory << @promptbuf
		@prompthistory.shift if @prompthistory.length > @prompthistlen
		@promptbuf = ''
		@promptpos = @promptbuf.length
		argint = proc {
			begin
				raise if not e = ExprParser.parse(lex)
			rescue
				log 'syntax error'
				return
			end
			e.bind(mem_binding(e)).reduce
		}

		cmd = lex.readtok
		cmd = cmd.raw if cmd
		nil while ntok = lex.readtok and ntok.type == :space
		lex.unreadtok ntok
		if @command.has_key? cmd
			@command[cmd].call(lex, argint)
		else
			if cmd and (poss = @command.keys.find_all { |c| c[0, cmd.length] == cmd }).length == 1
				@command[poss.first].call(lex, argint)
			else
				log 'unknown command'
			end
		end
	end
	
	def updatecodeptr
		@codeptr ||= @rs.regs_cache['eip']
		if @codeptr > @rs.regs_cache['eip'] or @codeptr < @rs.regs_cache['eip'] - 6*@win_code_height
			@codeptr = @rs.regs_cache['eip']
		elsif @codeptr != @rs.regs_cache['eip']
			addr = @codeptr
			addrs = []
			while addr < @rs.regs_cache['eip']
				addrs << addr
				o = @rs.mnemonic_di(addr).bin_length
				addr += ((o == 0) ? 1 : o)
			end
			if addrs.length > @win_code_height-4
				@codeptr = addrs[-(@win_code_height-4)]
			end
		end
		updatedataptr
	end

	def updatedataptr
		@dataptr = @watch.bind(mem_binding(@watch)).reduce if @watch
	end

	def singlestep
		@rs.singlestep
		updatecodeptr
	end
	def stepover
		@rs.stepover
		updatecodeptr
	end
	def cont(*a)
		@rs.cont(*a)
		updatecodeptr
	end
	def stepout
		@rs.stepout
		updatecodeptr
	end
	def syscall
		@rs.syscall
		updatecodeptr
	end

	def main_loop_inner
		@prompthistory = ['']
		@histptr = nil
		@running = true
		update
		while @running
			if not IO.select [$stdin], nil, nil, 0
				begin
					update
				rescue Errno::ESRCH
					break
				end
			end
			break if handle_keypress(Ansi.getkey)
		end
		@rs.checkbp
	end

	def handle_keypress(k)
			case k
			when 4: log 'exiting'; return true	 # eof
			when ?\e: focus = :prompt
			when :f5:  cont
			when :f6
				syscall
				log Rubstop::SYSCALLNR.index(@rs.regs_cache['orig_eax']) || @rs.regs_cache['orig_eax'].to_s
			when :f10: stepover
			when :f11: singlestep
			when :f12: stepout
			when :up
				case @focus
				when :prompt
					if not @histptr
						@prompthistory << @promptbuf
						@histptr = 2
					else
						@histptr += 1
						@histptr = 1 if @histptr > @prompthistory.length
					end
					@promptbuf = @prompthistory[-@histptr].dup
					@promptpos = @promptbuf.length
				when :data
					@dataptr -= 16
				when :code
					@codeptr ||= @rs.regs_cache['eip']
					@codeptr -= (1..10).find { |off| @rs.mnemonic_di(@codeptr-off).bin_length == off rescue false } || 10
				end
			when :down
				case @focus
				when :prompt
					if not @histptr
						@prompthistory << @promptbuf
						@histptr = @prompthistory.length
					else
						@histptr -= 1
						@histptr = @prompthistory.length if @histptr < 1
					end
					@promptbuf = @prompthistory[-@histptr].dup
					@promptpos = @promptbuf.length
				when :data
					@dataptr += 16
				when :code
					@codeptr ||= @rs.regs_cache['eip']
					@codeptr += (((o = @rs.mnemonic_di(@codeptr).bin_length) == 0) ? 1 : o)
				end
			when :left:  @promptpos -= 1 if @promptpos > 0
			when :right: @promptpos += 1 if @promptpos < @promptbuf.length
			when :home:  @promptpos = 0
			when :end:   @promptpos = @promptbuf.length
			when :backspace, 0x7f: @promptbuf[@promptpos-=1, 1] = '' if @promptpos > 0
			when :suppr: @promptbuf[@promptpos, 1] = '' if @promptpos < @promptbuf.length
			when :pgup
				case @focus
				when :prompt: @log_off += @win_prpt_height-3
				when :data: @dataptr -= 16*(@win_data_height-1)
				when :code
					@codeptr ||= @rs.regs_cache['eip']
					(@win_code_height-1).times {
						@codeptr -= (1..10).find { |off| @rs.mnemonic_di(@codeptr-off).bin_length == off rescue false } || 10
					}
				end
			when :pgdown
				case @focus
				when :prompt: @log_off -= @win_prpt_height-3
				when :data: @dataptr += 16*(@win_data_height-1)
				when :code
					@codeptr ||= @rs.regs_cache['eip']
					(@win_code_height-1).times { @codeptr += (((o = @rs.mnemonic_di(@codeptr).bin_length) == 0) ? 1 : o) }
				end
			when ?\t:
				if not @promptbuf[0, @promptpos].include? ' '
					poss = @command.keys.find_all { |c| c[0, @promptpos] == @promptbuf[0, @promptpos] }
					if poss.length > 1
						log poss.sort.join(' ')
					elsif poss.length == 1
						@promptbuf[0, @promptpos] = poss.first + ' '
						@promptpos = poss.first.length+1
					end
				end
			when ?\n: @histptr = nil ; exec_prompt rescue log "error: #$!"
			when 0x20..0x7e
				@promptbuf[@promptpos, 0] = k.chr
				@promptpos += 1
			else log "unknown key pressed #{k.inspect}"
			end
			nil
	end

	def load_commands
		ntok = nil
		@command['kill'] = proc { |lex, int|
			@rs.kill
			@running = false
			log 'killed'
		}
		@command['quit'] = @command['detach'] = @command['exit'] = proc { |lex, int|
			@rs.detach
			@running = false
		}
		@command['closeui'] = proc { |lex, int|
			@rs.logger = nil
			@running = false
		}
		@command['bpx'] = proc { |lex, int|
			addr = int[]
			@rs.bpx addr
		}
		@command['bphw'] = proc { |lex, int|
			type = lex.readtok.raw
			addr = int[]
			@rs.set_hwbp type, addr
		}
		@command['bl'] = proc { |lex, int|
			log "bpx at #{@rs.findsymbol(@rs.wantbp)}" if @rs.wantbp.kind_of? ::Integer
			@rs.breakpoints.sort.each { |addr, oct|
				log "bpx at #{@rs.findsymbol(addr)}"
			}
			(0..3).each { |dr|
				if @rs.regs_cache['dr7'] & (1 << (2*dr)) != 0
					log "bphw #{{0=>'x', 1=>'w', 2=>'?', 3=>'r'}[(@rs.regs_cache['dr7'] >> (16+4*dr)) & 3]} at #{@rs.findsymbol(@rs.regs_cache["dr#{dr}"])}"
				end
			}
		}
		@command['bc'] = proc { |lex, int|
			@rs.wantbp = nil if @rs.wantbp == @rs.regs_cache['eip']
			@rs.breakpoints.each { |addr, oct| @rs[addr] = oct }
			@rs.breakpoints.clear
			if @rs.regs_cache['dr7'] & 0xff != 0
				@rs.dr7 = 0 
				@rs.readregs
			end
		}
		@command['bt'] = proc { |lex, int| @rs.backtrace.each { |t| puts t } }
		@command['d'] =  proc { |lex, int| @dataptr = int[] || return }
		@command['db'] = proc { |lex, int| @datafmt = 'db' ; @dataptr = int[] || return }
		@command['dw'] = proc { |lex, int| @datafmt = 'dw' ; @dataptr = int[] || return }
		@command['dd'] = proc { |lex, int| @datafmt = 'dd' ; @dataptr = int[] || return }
		@command['r'] =  proc { |lex, int| 
			r = lex.readtok.raw
			nil while ntok = lex.readtok and ntok.type == :space
			if r == 'fl'
				flag = ntok.raw
				if i = Rubstop::EFLAGS.index(flag)
					@rs.eflags = @rs.regs_cache['eflags'] ^ (1 << i)
					readregs
				else
					log "bad flag #{flag}"
				end
			elsif not @rs.regs_cache[r]
				log "bad reg #{r}"
			elsif ntok
				lex.unreadtok ntok
				@rs.send r+'=', int[]
				@rs.readregs
			else
				log "#{r} = #{@rs.regs_cache[r]}"
			end
		}
		@command['run'] = @command['cont'] = proc { |lex, int|
			if tok = lex.readtok
				lex.unreadtok tok
				cont int[]
			else cont
			end
		}
		@command['syscall']    = proc { |lex, int| syscall }
		@command['singlestep'] = proc { |lex, int| singlestep }
		@command['stepover']   = proc { |lex, int| stepover }
		@command['stepout']    = proc { |lex, int| stepout }
		@command['g'] = proc { |lex, int| @rs.bpx int[], true ; cont }
		@command['u'] = proc { |lex, int| @codeptr = int[] || break }
		@command['has_pax'] = proc { |lex, int|
			if tok = lex.readtok
				lex.unreadtok tok
				@rs.has_pax = (int[] != 0)
			else @rs.has_pax = !@rs.has_pax
			end
			log "has_pax now #{@rs.has_pax}"
		}
		@command['loadsyms'] = proc { |lex, int| @rs.loadallsyms }
		@command['scansyms'] = proc { |lex, int| @rs.scansyms }
		@command['sym'] = proc { |lex, int|
			sym = ''
			sym << ntok.raw while ntok = lex.readtok
			s = @rs.symbols.values.grep(/#{sym}/)
			if s.empty?
				log "unknown symbol #{sym}"
			else
				s = @rs.symbols.keys.find_all { |k| s.include? @rs.symbols[k] }
				s.sort.each { |s| log "#{'%08x' % s} #{@rs.symbols_len[s].to_s.ljust 6} #{@rs.findsymbol(s)}" }
			end
		}
		@command['delsym'] = proc { |lex, int|
			addr = int[]
			log "deleted #{@rs.symbols.delete addr}"
			@rs.symbols_len.delete addr
		}
		@command['addsym'] = proc { |lex, int|
			name = lex.readtok.raw
			addr = int[]
			if t = lex.readtok
				lex.unreadtok t
				@rs.symbols_len[addr] = int[]
			else
				@rs.symbols_len[addr] = 1
			end
			@rs.symbols[addr] = name
		}
		@command['help'] = proc { |lex, int|
			log 'commands: (addr/values are things like dword ptr [ebp+(4*byte [eax])] ), type <tab> to see all commands'
			log ' bpx <addr>'
			log ' bphw [r|w|x] <addr>: debug register breakpoint'
			log ' bl: list breakpoints'
			log ' bc: clear breakpoints'
			log ' cont [<signr>]: continue the target sending a signal'
			log ' d/db/dw/dd [<addr>]: change data type/address'
			log ' g <addr>: set a bp at <addr> and run'
			log ' has_pax [0|1]: set has_pax flag (hwbp+0x60000000 instead of bpx)'
			log ' r <reg> [<value>]: show/change register'
			log ' r fl <flag>: toggle eflags bit'
			log ' loadsyms: load symbol information from mapped files (from /proc and disk)'
			log ' scansyms: scan memory for ELF headers'
			log ' sym <symbol regex>: show symbol information'
			log ' addsym <name> <addr> [<size>]'
			log ' delsym <addr>'
			log ' u <addr>: disassemble addr'
			log ' reload: reload lindebug source'
			log ' ruby <ruby code>: instance_evals ruby code in current instance'
			log ' closeui: detach from the underlying RubStop'
			log 'keys:'
			log ' F5: continue'
			log ' F6: syscall'
			log ' F10: step over'
			log ' F11: single step'
			log ' F12: step out (til next ret)'
			log ' pgup/pgdown: move command history'
		}
		@command['reload'] = proc { |lex, int| load $0 ; load_commands }
		@command['ruby'] = proc { |lex, int|
			str = ''
			str << ntok.raw while ntok = lex.readtok
			instance_eval str
		}
		@command['maps'] = proc { |lex, int|
			@rs.filemap.sort_by { |f, (b, e)| b }.each { |f, (b, e)|
				log "#{f.ljust 20} #{'%08x' % b} - #{'%08x' % e}"
			}
		}
		@command['resize'] = proc { |lex, int| resize }
		@command['watch'] = proc { |lex, int| @watch = ExprParser.parse(lex) ; updatedataptr }
		@command['wd'] = proc { |lex, int|
			@focus = :data
			if tok = lex.readtok
				lex.unreadtok tok
				@win_data_height = int[] || return
				resize
			end
		}
		@command['wc'] = proc { |lex, int|
			@focus = :code
			if tok = lex.readtok
				lex.unreadtok tok
				@win_code_height = int[] || return
				resize
			end
		}
		@command['wp'] = proc { |lex, int| @focus = :prompt }
		@command['?'] = proc { |lex, int|
			val = int[]
			log "#{val} 0x#{val.to_s(16)} #{[val].pack('L').inspect}"
		}
		@command['.'] = proc { |lex, int| @codeptr = nil }
	end
end


if $0 == __FILE__
	begin
		require 'samples/rubstop'
	rescue LoadError
	end

	LinDebug.new(Rubstop.new(ARGV.join(' '))).main_loop
end
