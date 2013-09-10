#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this exemple illustrates the use of the PTrace class to implement a pytstop-like functionnality
# Works on linux/x86
#

require 'metasm'

class Rubstop < Metasm::PTrace
  EFLAGS = {0 => 'c', 2 => 'p', 4 => 'a', 6 => 'z', 7 => 's', 9 => 'i', 10 => 'd', 11 => 'o'}
  # define accessors for registers
  %w[eax ebx ecx edx ebp esp edi esi eip orig_eax eflags dr0 dr1 dr2 dr3 dr6 dr7 cs ds es fs gs].each { |reg|
    define_method(reg) { peekusr(REGS_I386[reg.upcase]) & 0xffffffff }
    define_method(reg+'=') { |v|
      @regs_cache[reg] = v
      v = [v & 0xffffffff].pack('L').unpack('l').first if v >= 0x8000_0000
      pokeusr(REGS_I386[reg.upcase], v)
    }
  }

  def cont(signal=0)
    @ssdontstopbp = nil
    singlestep(true) if @wantbp
    super(signal)
    ::Process.waitpid(@pid)
    return if child.exited?
    @oldregs.update @regs_cache
    readregs
    checkbp
  end

  def singlestep(justcheck=false)
    super()
    ::Process.waitpid(@pid)
    return if child.exited?
    case @wantbp
    when ::Integer; bpx @wantbp ; @wantbp = nil
    when ::String; self.dr7 |= 1 << (2*@wantbp[2, 1].to_i) ; @wantbp = nil
    end
    return if justcheck
    @oldregs.update @regs_cache
    readregs
    checkbp
  end

  def stepover
    i = curinstr.instruction if curinstr
    if i and (i.opname == 'call' or (i.prefix and i.prefix[:rep]))
      eaddr = @regs_cache['eip'] + curinstr.bin_length
      bpx eaddr, true
      cont
    else
      singlestep
    end
  end

  def stepout
    # XXX @regs_cache..
    stepover until curinstr.opcode.name == 'ret'
    singlestep
  end

  def syscall
    @ssdontstopbp = nil
    singlestep(true) if @wantbp
    super()
    ::Process.waitpid(@pid)
    return if child.exited?
    @oldregs.update @regs_cache
    readregs
    checkbp
  end

  def state; :stopped end
  def ptrace; self end

  attr_accessor :pgm, :regs_cache, :breakpoints, :singleshot, :wantbp,
    :symbols, :symbols_len, :filemap, :has_pax, :oldregs
  def initialize(*a)
    super(*a)
    @pgm = Metasm::ExeFormat.new Metasm::Ia32.new
    @pgm.encoded = Metasm::EncodedData.new Metasm::LinuxRemoteString.new(@pid)
    @pgm.encoded.data.dbg = self
    @regs_cache = {}
    @oldregs = {}
    readregs
    @oldregs.update @regs_cache
    @breakpoints = {}
    @singleshot = {}
    @wantbp = nil
    @symbols = {}
    @symbols_len = {}
    @filemap = {}
    @has_pax = false

    stack = self[regs_cache['esp'], 0x1000].to_str.unpack('L*')
    stack.shift	# argc
    stack.shift until stack.empty? or stack.first == 0	# argv
    stack.shift
    stack.shift until stack.empty? or stack.first == 0	# envp
    stack.shift
    stack.shift until stack.empty? or stack.shift == 3	# find PHDR ptr in auxv
    if phdr = stack.shift
      phdr &= 0xffff_f000
      loadsyms phdr, phdr.to_s(16)
    end
  end

  def set_pax(bool)
    if bool
      @pgm.encoded.data.invalidate
      code = @pgm.encoded.data[eip, 4]
      if code != "\0\0\0\0" and @pgm.encoded.data[eip+0x6000_0000, 4] == code
        @has_pax = 'segmexec'
      else
        @has_pax = 'pax'
      end
    else
      @has_pax = false
    end
  end

  def readregs
    %w[eax ebx ecx edx esi edi esp ebp eip orig_eax eflags dr0 dr1 dr2 dr3 dr6 dr7 cs ds].each { |r| @regs_cache[r] = send(r) }
    @curinstr = nil if @regs_cache['eip'] != @oldregs['eip']
    @pgm.encoded.data.invalidate
  end

  def curinstr
    @curinstr ||= mnemonic_di
  end

  def child
    $?
  end

  def checkbp
    ::Process::waitpid(@pid, ::Process::WNOHANG) if not child
    return if not child
    if not child.stopped?
      if child.exited?;      log "process exited with status #{child.exitstatus}"
      elsif child.signaled?; log "process exited due to signal #{child.termsig} (#{Signal.list.index child.termsig})"
      else                log "process in unknown status #{child.inspect}"
      end
      return
    elsif child.stopsig != ::Signal.list['TRAP']
      log "process stopped due to signal #{child.stopsig} (#{Signal.list.index child.stopsig})"
      return	# do not check 0xcc at eip-1 ! ( if curinstr.bin_length == 1 )
    end
    ccaddr = @regs_cache['eip']-1
    if @breakpoints[ccaddr] and self[ccaddr] == 0xcc
      if @ssdontstopbp != ccaddr
        self[ccaddr] = @breakpoints.delete ccaddr
        self.eip = ccaddr
        @wantbp = ccaddr if not @singleshot.delete ccaddr
        @ssdontstopbp = ccaddr
      else
        @ssdontstopbp = nil
      end
    elsif @regs_cache['dr6'] & 15 != 0
      dr = (0..3).find { |dr_| @regs_cache['dr6'] & (1 << dr_) != 0 }
      @wantbp = "dr#{dr}" if not @singleshot.delete @regs_cache['eip']
      self.dr6 = 0
      self.dr7 = @regs_cache['dr7'] & (0xffff_ffff ^ (3 << (2*dr)))
      readregs
    end
  end

  def bpx(addr, singleshot=false)
    @singleshot[addr] = singleshot
    return if @breakpoints[addr]
    if @has_pax
      set_hwbp 'x', addr
    else
      begin
        @breakpoints[addr] = self[addr]
        self[addr] = 0xcc
      rescue Errno::EIO
        log 'i/o error when setting breakpoint, switching to PaX mode'
        set_pax true
        @breakpoints.delete addr
        bpx(addr, singleshot)
      end
    end
  end

  def mnemonic_di(addr = eip)
    @pgm.encoded.ptr = addr
    di = @pgm.cpu.decode_instruction(@pgm.encoded, addr)
    @curinstr = di if addr == @regs_cache['eip']
    di
  end

  def mnemonic(addr=eip)
    mnemonic_di(addr).instruction
  end

  def regs_dump
    [%w[eax ebx ecx edx orig_eax], %w[ebp esp edi esi eip]].map { |l|
      l.map { |reg| "#{reg}=#{'%08x' % @regs_cache[reg]}" }.join(' ')
    }.join("\n")
  end

  def findfilemap(s)
    @filemap.keys.find { |k| @filemap[k][0] <= s and @filemap[k][1] > s } || '???'
  end

  def findsymbol(k)
    file = findfilemap(k) + '!'
    if s = @symbols[k] ? k : @symbols.keys.find { |s_| s_ < k and s_ + @symbols_len[s_].to_i > k }
      file + @symbols[s] + (s == k ? '' : "+#{(k-s).to_s(16)}")
    else
      file + ('%08x' % k)
    end
  end

  def set_hwbp(type, addr, len=1)
    dr = (0..3).find { |dr_| @regs_cache['dr7'] & (1 << (2*dr_)) == 0 and @wantbp != "dr#{dr}" }
    if not dr
      log 'no debug reg available :('
      return false
    end
    @regs_cache['dr7'] &= 0xffff_ffff ^ (0xf << (16+4*dr))
    case type
    when 'x'; addr += (@has_pax == 'segmexec' ? 0x6000_0000 : 0)
    when 'r'; @regs_cache['dr7'] |= (((len-1)<<2)|3) << (16+4*dr)
    when 'w'; @regs_cache['dr7'] |= (((len-1)<<2)|1) << (16+4*dr)
    end
    send("dr#{dr}=", addr)
    self.dr6 = 0
    self.dr7 = @regs_cache['dr7'] | (1 << (2*dr))
    readregs
    true
  end

  def clearbreaks
    @wantbp = nil if @wantbp == @regs_cache['eip']
    @breakpoints.each { |addr, oct| self[addr, 1] = oct }
    @breakpoints.clear
    if @regs_cache['dr7'] & 0xff != 0
      self.dr7 = 0
      readregs
    end
  end

  def loadsyms(baseaddr, name)
    @loadedsyms ||= {}
    return if @loadedsyms[name] or self[baseaddr, 4] != "\x7fELF"
    @loadedsyms[name] = true

    set_status " loading symbols from #{name}..."
    e = Metasm::LoadedELF.load self[baseaddr, 0x100_0000]
    e.load_address = baseaddr
    begin
      e.decode
      #e = Metasm::ELF.decode_file name rescue return 	# read from disk
    rescue
      log "failed to load symbols from #{name}: #$!"
      ($!.backtrace - caller).each { |l| log l.chomp }
      @filemap[baseaddr.to_s(16)] = [baseaddr, baseaddr+0x1000]
      return
    end

    if e.tag['SONAME']
      name = e.tag['SONAME']
      return if name and @loadedsyms[name]
      @loadedsyms[name] = true
    end

    last_s = e.segments.reverse.find { |s| s.type == 'LOAD' }
    vlen = last_s.vaddr + last_s.memsz
    vlen -= baseaddr if e.header.type == 'EXEC'
    @filemap[name] = [baseaddr, baseaddr + vlen]

    oldsyms = @symbols.length
    e.symbols.each { |s|
      next if not s.name or s.shndx == 'UNDEF'
      sname = s.name
      sname = 'weak_'+sname if s.bind == 'WEAK'
      sname = 'local_'+sname if s.bind == 'LOCAL'
      v = s.value
      v = baseaddr + v if v < baseaddr
      @symbols[v] = sname
      @symbols_len[v] = s.size
    }
    if e.header.type == 'EXEC'
      @symbols[e.header.entry] = 'entrypoint'
    end
    set_status nil
    log "loaded #{@symbols.length-oldsyms} symbols from #{name} at #{'%08x' % baseaddr}"
  end

  def loadallsyms
    File.read("/proc/#{@pid}/maps").each { |l|
      name = l.split[5]
      loadsyms l.to_i(16), name if name and name[0] == ?/
    }
  end

  def loadmap(mapfile)
    # file fmt: addr type name eg 'c01001ba t setup_idt'
    minaddr = maxaddr = nil
    File.read(mapfile).each { |l|
      addr, type, name = l.chomp.split
      addr = addr.to_i(16)
      minaddr = addr if not minaddr or minaddr > addr
      maxaddr = addr if not maxaddr or maxaddr < addr
      @symbols[addr] = name
    }
    if minaddr
      @filemap[minaddr.to_s(16)] = [minaddr, maxaddr+1]
    end
  end

  def scansyms
    addr = 0
    fd = @pgm.encoded.data.readfd
    while addr <= 0xffff_f000
      addr = 0xc000_0000 if @has_pax and addr == 0x6000_0000
      log "scansym: #{'%08x' % addr}" if addr & 0x0fff_ffff == 0
      fd.pos = addr
      loadsyms(addr, '%08x'%addr) if (fd.read(4) == "\x7fELF" rescue false)
      addr += 0x1000
    end
  end

  def backtrace
    s = findsymbol(@regs_cache['eip'])
    if block_given?
      yield s
    else
      bt = []
      bt << s
    end
    fp = @regs_cache['ebp']
    while fp >= @regs_cache['esp'] and fp <= @regs_cache['esp']+0x10000
      s = findsymbol(self[fp+4, 4].unpack('L').first)
      if block_given?
        yield s
      else
        bt << s
      end
      fp = self[fp, 4].unpack('L').first
    end
    bt
  end

  def [](addr, len=nil)
    @pgm.encoded.data[addr, len]
  end
  def []=(addr, len, str=nil)
    @pgm.encoded.data[addr, len] = str
  end

  attr_accessor :logger
  def log(s)
    @logger ||= $stdout
    @logger.puts s
  end

  # set a temporary status info (nil for default value)
  def set_status(s)
    @logger ||= $stdout
    if @logger != $stdout
      @logger.statusline = s
    else
      s ||= ' '*72
      @logger.print s + "\r"
      @logger.flush
    end
  end
end

if $0 == __FILE__
  # start debugging
  rs = Rubstop.new(ARGV.shift)

  begin
    while rs.child.stopped? and rs.child.stopsig == Signal.list['TRAP']
      if $VERBOSE
        puts "#{'%08x' % rs.eip} #{rs.mnemonic}"
        rs.singlestep
      else
        rs.syscall ; rs.syscall	# wait return of syscall
        puts "#{rs.orig_eax.to_s.ljust(3)} #{rs.syscallnr.index rs.orig_eax}"
      end
    end
    p rs.child
    puts rs.regs_dump
  rescue Interrupt
    rs.detach rescue nil
    puts 'interrupted!'
  rescue Errno::ESRCH
  end
end
