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
    ttys = ''.ljust(256)
    $stdin.ioctl(TCGETS, ttys)
    tty = ttys.unpack('C*')
    if bool
      tty[12] &= ~(ECHO|CANON)
    else
      tty[12] |= ECHO|CANON
    end
    $stdin.ioctl(TCSETS, tty.pack('C*'))
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

class LinDebug
  attr_accessor :win_reg_height, :win_data_height, :win_code_height, :win_prpt_height
  def init_screen
    Ansi.set_term_canon(true)
    @win_reg_height = 2
    @win_data_height = 20
    @win_code_height = 20
    resize
  end

  def fini_screen
    Ansi.set_term_canon(false)
    $stdout.write Ansi.color(:normal, :reset)
    $stdout.flush
  end

  def win_data_start; @win_reg_height end
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
    @rs.set_log_proc { |l| add_log l }
    @datafmt = 'db'

    @prompthistlen = 20
    @prompthistory = []
    @promptloglen = 200
    @promptlog = []
    @promptbuf = ''
    @promptpos = 0
    @log_off = 0
    @console_width = 80
    @oldregs = {}

    @running = false
    @focus = :prompt
    @command = {}
    load_commands
    trap('WINCH') { resize }
  end

  def init_rs
    @codeptr = @dataptr = @rs.pc	# avoid initial faults
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
      puts $!, $!.backtrace
    end
    puts @promptlog.last
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
    lines = screenlines.lines
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
    pvrsz = 0
    words = @rs.register_list.map { |r|
      rs = r.to_s.rjust(pvrsz)
      pvrsz = rs.length
      rv = @rs[r]
      ["#{rs}=%0#{@rs.register_size[r]/4}X " % rv,
        (@oldregs[r] != rv)]
    } + @rs.flag_list.map { |fl|
      fv = @rs.get_flag(fl)
      [fv ? fl.to_s.upcase : fl.to_s.downcase,
        (@oldregs[fl] != fv)]
    }

    text = ' '
    linelen = 1	# line length w/o ansi colors

    owr = @win_reg_height
    @win_reg_height = 1
    words.each { |w, changed|
      if linelen + w.length >= @console_width - 1
        text << (' '*([@console_width-linelen, 0].max)) << "\n "
        linelen = 1
        @win_reg_height += 1
      end

      text << Color[:changed] if changed
      text << w
      text << Color[:normal] if changed
      text << ' '

      linelen += w.length+1
    }
    resize if owr != @win_reg_height
    text << (' '*([@console_width-linelen, 0].max)) << "\n"
  end

  def updatecode
    once(:updatecode, "...\n"*@win_code_height) { _updatecode }
  end

  def _updatecode
    if @codeptr
      addr = @codeptr
    elsif @oldregs[@rs.register_pc] and @oldregs[@rs.register_pc] < @rs.pc and @oldregs[@rs.register_pc] + 8 >= @rs.pc
      addr = @oldregs[@rs.register_pc]
    else
      addr = @rs.pc
    end
    @codeptr = addr

    addrsz = @rs.register_size[@rs.register_pc]
    addrfmt = "%0#{addrsz/4}X"
    if not @rs.addr2module(addr) and @rs.shortname !~ /remote/
      base = addr & ((1 << addrsz) - 0x1000)
      @noelfsig ||= {}	# cache elfmagic notfound
      if not @noelfsig[base] and base < ((1 << addrsz) - 0x1_0000)
        self.statusline = " scanning for elf header at #{addrfmt % base}"
        128.times {
          @statusline = " scanning for elf header at #{addrfmt % base}"
          if not @noelfsig[base] and @rs[base, Metasm::ELF::MAGIC.length] == Metasm::ELF::MAGIC
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
    title = @rs.addrname(addr)
    pre  = [@console_width-100, 6].max
    post = @console_width - (pre + title.length + 2)
    text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post) << Color[:normal] << "\n"

    seg = ''
    seg = ('%04X' % @rs['cs']) << ':' if @rs.cpu.shortname =~ /ia32|x64/

    cnt = @win_code_height
    while (cnt -= 1) > 0
      if @rs.symbols[addr]
        text << ('    ' << @rs.symbols[addr] << ?:) << Ansi::ClearLineAfter << "\n"
        break if (cnt -= 1) <= 0
      end
      text << Color[:hilight] if addr == @rs.pc
      text << seg
      if @rs.shortname =~ /remote/ and @rs.realmode
        text << (addrfmt % (addr - 16*@rs['cs']))
      else
        text << (addrfmt % addr)
      end
      di = @rs.di_at(addr)
      di = nil if di and addr < @rs.pc and addr+di.bin_length > @rs.pc
      len = (di ? di.bin_length : 1)
      text << '  '
      text << @rs.memory[addr, [len, 10].min].to_s.unpack('C*').map { |c| '%02X' % c }.join.ljust(22)
      if di
        text <<
        if addr == @rs.pc
          "*#{di.instruction}".ljust([@console_width-(addrsz/4+seg.length+24), 0].max)
        else
          " #{di.instruction}" << Ansi::ClearLineAfter
        end
      else
        text << ' <unk>' << Ansi::ClearLineAfter
      end
      text << Color[:normal] if addr == @rs.pc
      addr += len
      text << "\n"
    end
    text
  end

  def updatedata
    once(:updatedata, "...\n"*@win_data_height) { _updatedata }
  end

  def _updatedata
    addrsz = @rs.register_size[@rs.register_pc]
    addrfmt = "%0#{addrsz/4}X"

    @dataptr &= ((1 << addrsz) - 1)
    addr = @dataptr

    text = ''
    text << Color[:border]
    title = @rs.addrname(addr)
    pre  = [@console_width-100, 6].max
    post = [@console_width - (pre + title.length + 2), 0].max
    text << Ansi.hline(pre) << ' ' << title << ' ' << Ansi.hline(post) << Color[:normal] << "\n"

    seg = ''
    seg = ('%04X' % @rs['ds']) << ':' if @rs.cpu.shortname =~ /^ia32/

    cnt = @win_data_height
    while (cnt -= 1) > 0
      raw = @rs.memory[addr, 16].to_s
      text << seg << (addrfmt % addr) << '  '
      case @datafmt
      when 'db'; text << raw[0,8].unpack('C*').map { |c| '%02x ' % c }.join << ' ' <<
           raw[8,8].to_s.unpack('C*').map { |c| '%02x ' % c }.join
      when 'dw'; text << raw.unpack('S*').map { |c| '%04x ' % c }.join
      when 'dd'; text << raw.unpack('L*').map { |c| '%08x ' % c }.join
      end
      text << ' ' << raw.unpack('C*').map { |c| (0x20..0x7e).include?(c) ? c : 0x2e }.pack('C*')
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
    if @win_data_height + @win_code_height + @win_reg_height + 3 > @console_height
      @win_data_height = @console_height/2 - 4
      @win_code_height = @console_height/2 - 4
    end
    @win_prpt_height = @console_height-(@win_data_height+@win_code_height+@win_reg_height) - 1
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

  def add_log(l)
    log l
    puts l if not @running
    update rescue puts l
  end

  def exec_prompt
    @log_off = 0
    log ':'+@promptbuf
    return if @promptbuf == ''
    str = @promptbuf
    @prompthistory << @promptbuf
    @prompthistory.shift if @prompthistory.length > @prompthistlen
    @promptbuf = ''
    @promptpos = @promptbuf.length

    cmd, str = str.split(/\s+/, 2)
    if @command.has_key? cmd
      @command[cmd].call(str.to_s)
    else
      if cmd and (poss = @command.keys.find_all { |c| c[0, cmd.length] == cmd }).length == 1
        @command[poss.first].call(str.to_s)
      else
        log 'unknown command'
      end
    end
  end

  def preupdate
    @rs.register_list.each { |r| @oldregs[r] = @rs[r] }
    @rs.flag_list.each { |fl| @oldregs[fl] = @rs.get_flag(fl) }
  end

  def updatecodeptr
    @codeptr ||= @rs.pc
    if @codeptr > @rs.pc or @codeptr < @rs.pc - 6*@win_code_height
      @codeptr = @rs.pc
    elsif @codeptr != @rs.pc
      addr = @codeptr
      addrs = []
      while addr < @rs.pc
        addrs << addr
        o = ((di = @rs.di_at(addr)) ? di.bin_length : 0)
        addr += ((o == 0) ? 1 : o)
      end
      if addrs.length > @win_code_height-4
        @codeptr = addrs[-(@win_code_height-4)]
      end
    end
    updatedataptr
  end

  def updatedataptr
  end

  def singlestep
    self.statusline = ' target singlestepping...'
    preupdate
    @rs.singlestep_wait
    updatecodeptr
    @statusline = nil
  end
  def stepover
    self.statusline = ' target running...'
    preupdate
    @rs.stepover_wait
    updatecodeptr
    @statusline = nil
  end
  def cont(*a)
    self.statusline = ' target running...'
    preupdate
    @rs.continue_wait(*a)
    updatecodeptr
    @statusline = nil
  end
  def stepout
    self.statusline = ' target running...'
    preupdate
    @rs.stepout_wait
    updatecodeptr
    @statusline = nil
  end
  def syscall
    self.statusline = ' target running to next syscall...'
    preupdate
    @rs.syscall_wait
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
  end

  def handle_keypress(k)
      case k
      when ?\4; log 'exiting'; return true	 # eof
      when ?\e; @focus = :prompt
      when :f5;  cont
      when :f6;  syscall
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
          @codeptr ||= @rs.pc
          @codeptr -= (1..10).find { |off|
            di = @rs.di_at(@codeptr-off)
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
          @codeptr ||= @rs.pc
          di = @rs.di_at(@codeptr)
          @codeptr += (di ? (di.bin_length || 1) : 1)
        end
      when :left;  @promptpos -= 1 if @promptpos > 0
      when :right; @promptpos += 1 if @promptpos < @promptbuf.length
      when :home;  @promptpos = 0
      when :end;   @promptpos = @promptbuf.length
      when :backspace, ?\x7f; @promptbuf[@promptpos-=1, 1] = '' if @promptpos > 0
      when :suppr; @promptbuf[@promptpos, 1] = '' if @promptpos < @promptbuf.length
      when :pgup
        case @focus
        when :prompt; @log_off += @win_prpt_height-3
        when :data; @dataptr -= 16*(@win_data_height-1)
        when :code
          @codeptr ||= @rs.pc
          (@win_code_height-1).times {
            @codeptr -= (1..10).find { |off|
              di = @rs.di_at(@codeptr-off)
              di.bin_length == off if di
            } || 10
          }
        end
      when :pgdown
        case @focus
        when :prompt; @log_off -= @win_prpt_height-3
        when :data; @dataptr += 16*(@win_data_height-1)
        when :code
          @codeptr ||= @rs.pc
          (@win_code_height-1).times { @codeptr += ((o = @rs.di_at(@codeptr)) ? [o.bin_length, 1].max : 1) }
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
      when ?\ ..?~
        @promptbuf[@promptpos, 0] = k.chr
        @promptpos += 1
      else log "unknown key pressed #{k.inspect}"
      end
      nil
  end

  def load_commands
    @command['kill'] = lambda { |str|
      @rs.kill
      @running = false
      log 'killed'
    }
    @command['quit'] = @command['detach'] = @command['exit'] = lambda { |str|
      @rs.detach
      @running = false
    }
    @command['closeui'] = lambda { |str|
      @running = false
    }
    @command['bpx'] = lambda { |str|
      @rs.bpx @rs.resolve(str)
    }
    @command['bphw'] = @command['hwbp'] = lambda { |str|
      type, str = str.split(/\s+/, 2)
      @rs.hwbp @rs.resolve(str.to_s), type
    }
    @command['bt'] = lambda { |str| @rs.stacktrace { |a,t| add_log "#{'%x' % a} #{t}" } }
    @command['d'] =  lambda { |str| @dataptr = @rs.resolve(str) if str.length > 0 }
    @command['db'] = lambda { |str| @datafmt = 'db' ; @dataptr = @rs.resolve(str) if str.length > 0 }
    @command['dw'] = lambda { |str| @datafmt = 'dw' ; @dataptr = @rs.resolve(str) if str.length > 0 }
    @command['dd'] = lambda { |str| @datafmt = 'dd' ; @dataptr = @rs.resolve(str) if str.length > 0 }
    @command['r'] =  lambda { |str|
      r, str = str.split(/\s+/, 2)
      if r == 'fl'
        @rs.toggle_flag(str.to_sym)
      elsif not @rs[r]
        log "bad reg #{r}"
      elsif str and str.length > 0
        @rs[r] = @rs.resolve(str)
      else
        log "#{r} = #{@rs[r]}"
      end
    }
    @command['g'] = lambda { |str|
      @rs.go @rs.resolve(str)
    }
    @command['u'] = lambda { |str| @codeptr = @rs.resolve(str) }
    @command['ruby'] = lambda { |str| instance_eval str }
    @command['wd'] = lambda { |str|
      @focus = :data
      if str.length > 0
        @win_data_height = @rs.resolve(str)
        resize
      end
    }
    @command['wc'] = lambda { |str|
      @focus = :code
      if str.length > 0
        @win_code_height = @rs.resolve(str)
        resize
      end
    }
    @command['wp'] = lambda { |str| @focus = :prompt }
    @command['?'] = lambda { |str|
      val = @rs.resolve(str)
      log "#{val} 0x#{val.to_s(16)} #{[val].pack('L').inspect}"
    }
    @command['syscall'] = lambda { |str|
      @rs.syscall_wait(str)
    }
  end
end


if $0 == __FILE__
  require 'optparse'
  opts = { :sc_cpu => 'Ia32' }
  OptionParser.new { |opt|
    opt.on('-m map', '--map filemap') { |f| opts[:filemap] = f }
    opt.on('--cpu cpu') { |c| opts[:sc_cpu] = c }
  }.parse!(ARGV)

  case ARGV.first
  when /^(tcp:|udp:)?..+:/, /^ser:/
    opts[:sc_cpu] = eval(opts[:sc_cpu]) if opts[:sc_cpu] =~ /[.(\s:]/
    opts[:sc_cpu] = opts[:sc_cpu].new if opts[:sc_cpu].kind_of?(::Class)
    rs = Metasm::GdbRemoteDebugger.new(ARGV.first, opts[:sc_cpu])
  else
    rs = Metasm::LinDebugger.new(ARGV.join(' '))
  end
  rs.load_map(opts[:filemap]) if opts[:filemap]
  LinDebug.new(rs).main_loop
end
