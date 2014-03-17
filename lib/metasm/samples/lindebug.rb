#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
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
      when :bold; 2
      when :negative; 7
      when :normal; 22
      when :positive; 27
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
    raise 'nonblocking $stdin?' if not c
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
      case c; when ?a..?z, ?A..?Z, ?~; break end
    end
    ESC_SEQ[seq] || seq
  end
end

class Indirect < Metasm::ExpressionType
  attr_accessor :ptr, :sz
  UNPACK_STR = {1 => 'C', 2 => 'S', 4 => 'L'}
  def initialize(ptr, sz) @ptr, @sz = ptr, sz end
  def bind(bd)
    raw = bd['tracer_memory'][@ptr.bind(bd).reduce, @sz]
    Metasm::Expression[raw.unpack(UNPACK_STR[@sz]).first]
  end
  def externals ; @ptr.externals end
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
    else super(lex, tok)
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
    super(lex)
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
    $stdout.write Ansi.color(:normal, :reset)
    $stdout.flush
  end

  def win_data_start; 2 end
  def win_code_start; win_data_start+win_data_height end
  def win_prpt_start; win_code_start+win_code_height end

  Color = {:changed => Ansi.color(:cyan, :bold), :border => Ansi.color(:green),
    :normal => Ansi.color(:white, :black, :normal), :hilight => Ansi.color(:blue, :white, :normal),
    :status => Ansi.color(:black, :cyan)}

  # yields but keep from reentring (return defretval in this case)
  def once(name, defretval=nil)
    @once ||= {}
    if not @once[name]
      @once[name] = true
      begin
        defretval = yield
      ensure
        @once[name] = false
      end
    end
    defretval
  end

  attr_accessor :dataptr, :codeptr, :rs, :promptlog, :command
  def initialize(rs)
    @rs = rs
    @rs.logger = self
    @datafmt = 'db'
    @watch = nil

    @prompthistlen = 20
    @prompthistory = []
    @promptloglen = 200
    @promptlog = []
    @promptbuf = ''
    @promptpos = 0
    @log_off = 0
    @console_width = 80

    @running = false
    @focus = :prompt
    @command = {}
    load_commands
    trap('WINCH') { resize }
  end

  def init_rs
    @codeptr = @dataptr = @rs.regs_cache['eip']	# avoid initial faults
  end

  def main_loop
    begin
      begin
        init_screen
        init_rs
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

  # optimize string to display to stdout
  # currently only skips unchanged lines
  # could also match end of lines (spaces), but would need to check for color codes etc
  def optimize_screen(buf)
  end

  # display the text buffer screenlines to the screen, leaves the cursor at (cursx, cursy), converts cursor pos from 0-base to 1-base
  # screenlines is a big text buffer with 1 line per tobeshown screen line (e.g. no Ansi cursor pos)
  # screenlines must be screen wide
  def display_screen(screenlines, cursx, cursy)

    @oldscreenbuf ||= []
    lines = screenlines.to_a
    oldlines = @oldscreenbuf
    @oldscreenbuf = lines
    screenlines = lines.zip(oldlines).map { |l, ol| l == ol ? "\n" : l }.join

    while screenlines[-1] == ?\n
      screenlines.chop!
    end
    starty = 1
    while screenlines[0] == ?\n
      screenlines = screenlines[1..-1]
      starty += 1
    end

    $stdout.write Ansi.set_cursor_pos(starty, 1) + screenlines + Ansi.set_cursor_pos(cursy+1, cursx+1)

    $stdout.flush
  end

  def update
    return if not @running
    display_screen updateregs + updatedata + updatecode + updateprompt, @promptpos+1, @console_height-2
  end

  def updateregs
    once(:updateregs, "\n\n") { _updateregs }
  end

  def _updateregs
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
    text << (' '*([@console_width-x, 0].max)) << "\n" << ' '
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
    text << (' '*([@console_width-x, 0].max)) << "\n"
  end

  def updatecode
    once(:updatecode, "...\n"*@win_code_height) { _updatecode }
  end

  def _updatecode
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
      @noelfsig ||= {}	# cache elfmagic notfound
      if not @noelfsig[base] and base < 0xc000_0000
        self.statusline = " scanning for elf header at #{'%08X' % base}"
        128.times {
          @statusline = " scanning for elf header at #{'%08X' % base}"
          if not @noelfsig[base] and @rs[base, 4] == Metasm::ELF::MAGIC
            @rs.loadsyms(base, base.to_s(16))
            break
          else
            @noelfsig[base] = true	# XXX an elf may be mmaped here later..
          end
          base -= 0x1000
          break if base < 0
        }
        self.statusline = nil
      end
    end

    text = ''
    text << Color[:border]
    title = @rs.findsymbol(addr)
    pre  = [@console_width-100, 6].max
    post = @console_width - (pre + title.length + 2)
    text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post) << Color[:normal] << "\n"

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
          "*#{di.instruction}".ljust([@console_width-37, 0].max)
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
    once(:updatedata, "...\n"*@win_data_height) { _updatedata }
  end

  def _updatedata
    @dataptr &= 0xffff_ffff
    addr = @dataptr

    text = ''
    text << Color[:border]
    title = @rs.findsymbol(addr)
    pre  = [@console_width-100, 6].max
    post = [@console_width - (pre + title.length + 2), 0].max
    text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post) << Color[:normal] << "\n"

    cnt = @win_data_height
    while (cnt -= 1) > 0
      raw = @rs[addr, 16].to_s
      text << ('%04X' % @rs.regs_cache['ds']) << ':' << ('%08X' % addr) << '  '
      case @datafmt
      when 'db'; text << raw[0,8].unpack('C*').map { |c| '%02x ' % c }.join << ' ' <<
           raw[8,8].to_s.unpack('C*').map { |c| '%02x ' % c }.join
      when 'dw'; text << raw.unpack('S*').map { |c| '%04x ' % c }.join
      when 'dd'; text << raw.unpack('L*').map { |c| '%08x ' % c }.join
      end
      text << ' ' << raw.unpack('C*').map { |c| (0x20..0x7e).include?(c) ? c : ?. }.pack('C*')
      text << Ansi::ClearLineAfter << "\n"
      addr += 16
    end
    text
  end

  def updateprompt
    once(:updateprompt, "\n"*@win_prpt_height) { _updateprompt }
  end

  def _updateprompt
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
    text << Color[:status] << statusline.chomp.ljust(@console_width) << Color[:normal]
  end

  def statusline
    @statusline ||= '    Enter a command (help for help)'
  end
  def statusline=(s)
    @statusline = s
    update
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
    @oldscreenbuf = []
    update
  end

  def log(*strs)
    strs.each { |str|
    raise str.inspect if not str.kind_of? ::String
    str = str.chomp
    if str.length > @console_width
      # word wrap
      str.scan(/.{0,#@console_width}/) { |str_| log str_ }
      return
    end
    @promptlog << str
    @promptlog.shift if @promptlog.length > @promptloglen
    }
  end

  def puts(*s)
    s.each { |s_| log s_.to_s }
    super(*s) if not @running
    update rescue super(*s)
  end

  def mem_binding(expr)
    b = @rs.regs_cache.dup
    ext = expr.externals
    (ext - @rs.regs_cache.keys).each { |ex|
      if not s = @rs.symbols.index(ex)
        near = @rs.symbols.values.grep(/#{ex}/i)
        if near.length > 1
          log "#{ex.inspect} is ambiguous: #{near.inspect}"
          return {}
        elsif near.empty?
          log "unknown value #{ex.inspect}"
          return {}
        else
          log "using #{near.first.inspect} for #{ex.inspect}"
          s = @rs.symbols.index(near.first)
        end
      end
      b[ex] = s
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
    argint = lambda {
      begin
        raise if not e = ExprParser.parse(lex)
      rescue
        log 'syntax error'
        return
      end
      e = e.bind(mem_binding(e)).reduce
      if e.kind_of? Integer; e
      else log "could not resolve #{e.inspect}" ; nil
      end
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
        o = ((di = @rs.mnemonic_di(addr)) ? di.bin_length : 0)
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
    self.statusline = ' target singlestepping...'
    @rs.singlestep
    updatecodeptr
    @statusline = nil
  end
  def stepover
    self.statusline = ' target running...'
    @rs.stepover
    updatecodeptr
    @statusline = nil
  end
  def cont(*a)
    self.statusline = ' target running...'
    @rs.cont(*a)
    updatecodeptr
    @statusline = nil
  end
  def stepout
    self.statusline = ' target running...'
    @rs.stepout
    updatecodeptr
    @statusline = nil
  end
  def syscall
    self.statusline = ' target running to next syscall...'
    @rs.syscall
    updatecodeptr
    @statusline = nil
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
      when 4; log 'exiting'; return true	 # eof
      when ?\e; focus = :prompt
      when :f5;  cont
      when :f6
        syscall
        log @rs.syscallnr.index(@rs.regs_cache['orig_eax']) || @rs.regs_cache['orig_eax'].to_s
      when :f10; stepover
      when :f11; singlestep
      when :f12; stepout
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
          @codeptr -= (1..10).find { |off|
            di = @rs.mnemonic_di(@codeptr-off)
            di.bin_length == off if di
          } || 10
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
          di = @rs.mnemonic_di(@codeptr)
          @codeptr += (di ? (di.bin_length || 1) : 1)
        end
      when :left;  @promptpos -= 1 if @promptpos > 0
      when :right; @promptpos += 1 if @promptpos < @promptbuf.length
      when :home;  @promptpos = 0
      when :end;   @promptpos = @promptbuf.length
      when :backspace, 0x7f; @promptbuf[@promptpos-=1, 1] = '' if @promptpos > 0
      when :suppr; @promptbuf[@promptpos, 1] = '' if @promptpos < @promptbuf.length
      when :pgup
        case @focus
        when :prompt; @log_off += @win_prpt_height-3
        when :data; @dataptr -= 16*(@win_data_height-1)
        when :code
          @codeptr ||= @rs.regs_cache['eip']
          (@win_code_height-1).times {
            @codeptr -= (1..10).find { |off|
              di = @rs.mnemonic_di(@codeptr-off)
              di.bin_length == off if di
            } || 10
          }
        end
      when :pgdown
        case @focus
        when :prompt; @log_off -= @win_prpt_height-3
        when :data; @dataptr += 16*(@win_data_height-1)
        when :code
          @codeptr ||= @rs.regs_cache['eip']
          (@win_code_height-1).times { @codeptr += ((o = @rs.mnemonic_di(@codeptr)) ? [o.bin_length, 1].max : 1) }
        end
      when ?\t
        if not @promptbuf[0, @promptpos].include? ' '
          poss = @command.keys.find_all { |c| c[0, @promptpos] == @promptbuf[0, @promptpos] }
          if poss.length > 1
            log poss.sort.join(' ')
          elsif poss.length == 1
            @promptbuf[0, @promptpos] = poss.first + ' '
            @promptpos = poss.first.length+1
          end
        end
      when ?\n
        @histptr = nil
        begin
          exec_prompt
        rescue Exception
          log "error: #$!", *$!.backtrace
        end
      when 0x20..0x7e
        @promptbuf[@promptpos, 0] = k.chr
        @promptpos += 1
      else log "unknown key pressed #{k.inspect}"
      end
      nil
  end

  def load_commands
    ntok = nil
    @command['kill'] = lambda { |lex, int|
      @rs.kill
      @running = false
      log 'killed'
    }
    @command['quit'] = @command['detach'] = @command['exit'] = lambda { |lex, int|
      @rs.detach
      @running = false
    }
    @command['closeui'] = lambda { |lex, int|
      @rs.logger = nil
      @running = false
    }
    @command['bpx'] = lambda { |lex, int|
      addr = int[]
      @rs.bpx addr
    }
    @command['bphw'] = lambda { |lex, int|
      type = lex.readtok.raw
      addr = int[]
      @rs.set_hwbp type, addr
    }
    @command['bl'] = lambda { |lex, int|
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
    @command['bc'] = lambda { |lex, int|
      @rs.clearbreaks
    }
    @command['bt'] = lambda { |lex, int| @rs.backtrace { |t| puts t } }
    @command['d'] =  lambda { |lex, int| @dataptr = int[] || return }
    @command['db'] = lambda { |lex, int| @datafmt = 'db' ; @dataptr = int[] || return }
    @command['dw'] = lambda { |lex, int| @datafmt = 'dw' ; @dataptr = int[] || return }
    @command['dd'] = lambda { |lex, int| @datafmt = 'dd' ; @dataptr = int[] || return }
    @command['r'] =  lambda { |lex, int|
      r = lex.readtok.raw
      nil while ntok = lex.readtok and ntok.type == :space
      if r == 'fl'
        flag = ntok.raw
        if i = Rubstop::EFLAGS.index(flag)
          @rs.eflags ^= 1 << i
          @rs.readregs
        else
          log "bad flag #{flag}"
        end
      elsif not @rs.regs_cache[r]
        log "bad reg #{r}"
      elsif ntok
        lex.unreadtok ntok
        newval = int[]
        if newval and newval.kind_of? ::Integer
          @rs.send r+'=', newval
          @rs.readregs
        end
      else
        log "#{r} = #{@rs.regs_cache[r]}"
      end
    }
    @command['run'] = @command['cont'] = lambda { |lex, int|
      if tok = lex.readtok
        lex.unreadtok tok
        cont int[]
      else cont
      end
    }
    @command['syscall']    = lambda { |lex, int| syscall }
    @command['singlestep'] = lambda { |lex, int| singlestep }
    @command['stepover']   = lambda { |lex, int| stepover }
    @command['stepout']    = lambda { |lex, int| stepout }
    @command['g'] = lambda { |lex, int|
      target = int[]
      @rs.singlestep if @rs.regs_cache['eip'] == target
      @rs.bpx target, true
      cont
    }
    @command['u'] = lambda { |lex, int| @codeptr = int[] || break }
    @command['has_pax'] = lambda { |lex, int|
      if tok = lex.readtok
        lex.unreadtok tok
        if (int[] == 0)
          @rs.set_pax false
        else
          @rs.set_pax true
        end
      else @rs.set_pax !@rs.has_pax
      end
      log "has_pax now #{@rs.has_pax}"
    }
    @command['loadsyms'] = lambda { |lex, int|
      mapfile = ''
      mapfile << ntok.raw while ntok = lex.readtok
      if mapfile != ''
        @rs.loadmap mapfile
      else
        @rs.loadallsyms
      end
    }
    @command['scansyms'] = lambda { |lex, int| @rs.scansyms }
    @command['sym'] = lambda { |lex, int|
      sym = ''
      sym << ntok.raw while ntok = lex.readtok
      s = []
             @rs.symbols.each { |k, v|
        s << k if v =~ /#{sym}/
      }
      if s.empty?
        log "unknown symbol #{sym}"
      else
        s.sort.each { |s_| log "#{'%08x' % s_} #{@rs.symbols_len[s_].to_s.ljust 6} #{@rs.findsymbol(s_)}" }
      end
    }
    @command['delsym'] = lambda { |lex, int|
      addr = int[]
      log "deleted #{@rs.symbols.delete addr}"
      @rs.symbols_len.delete addr
    }
    @command['addsym'] = lambda { |lex, int|
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
    @command['help'] = lambda { |lex, int|
      log 'commands: (addr/values are things like dword ptr [ebp+(4*byte [eax])] ), type <tab> to see all commands'
      log ' bpx <addr>'
      log ' bphw [r|w|x] <addr>: debug register breakpoint'
      log ' bl: list breakpoints'
      log ' bc: clear breakpoints'
      log ' cont [<signr>]: continue the target sending a signal'
      log ' d/db/dw/dd [<addr>]: change data type/address'
      log ' g <addr>: set a bp at <addr> and run'
      log ' has_pax [0|1]: set has_pax flag'
      log ' loadsyms: load symbol information from mapped files (from /proc and disk)'
      log ' ma <addr> <ascii>: write memory'
      log ' mx <addr> <hex>: write memory'
      log ' maps: list maps'
      log ' r <reg> [<value>]: show/change register'
      log ' r fl <flag>: toggle eflags bit'
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
    @command['reload'] = lambda { |lex, int| load $0 ; load_commands }
    @command['ruby'] = lambda { |lex, int|
      str = ''
      str << ntok.raw while ntok = lex.readtok
      instance_eval str
    }
    @command['maps'] = lambda { |lex, int|
      @rs.filemap.sort_by { |f, (b, e)| b }.each { |f, (b, e)|
        log "#{f.ljust 20} #{'%08x' % b} - #{'%08x' % e}"
      }
    }
    @command['ma'] = lambda { |lex, int|
      addr = int[]
      str = ''
      str << ntok.raw while ntok = lex.readtok
      @rs[addr, str.length] = str
    }
    @command['mx'] = lambda { |lex, int|
      addr = int[]
      data = [lex.readtok.raw].pack('H*')
      @rs[addr, data.length] = data
    }
    @command['resize'] = lambda { |lex, int| resize }
    @command['watch'] = lambda { |lex, int| @watch = ExprParser.parse(lex) ; updatedataptr }
    @command['wd'] = lambda { |lex, int|
      @focus = :data
      if tok = lex.readtok
        lex.unreadtok tok
        @win_data_height = int[] || return
        resize
      end
    }
    @command['wc'] = lambda { |lex, int|
      @focus = :code
      if tok = lex.readtok
        lex.unreadtok tok
        @win_code_height = int[] || return
        resize
      end
    }
    @command['wp'] = lambda { |lex, int| @focus = :prompt }
    @command['?'] = lambda { |lex, int|
      val = int[]
      log "#{val} 0x#{val.to_s(16)} #{[val].pack('L').inspect}"
    }
    @command['.'] = lambda { |lex, int| @codeptr = nil }
  end
end


if $0 == __FILE__
  require 'optparse'
  filemap = nil
  OptionParser.new { |opt|
    opt.on('-m map', '--map filemap') { |f| filemap = f }
  }.parse!(ARGV)

  if not defined? Rubstop
    if ARGV.first =~ /:/
      stub = 'gdbclient'
    else
      stub = 'rubstop'
    end
    require File.join(File.dirname(__FILE__), stub)
  end

  rs = Rubstop.new(ARGV.join(' '))
  rs.loadmap(filemap) if filemap
  LinDebug.new(rs).main_loop
end
