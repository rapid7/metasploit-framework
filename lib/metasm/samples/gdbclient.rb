#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

#
# this is a rubstop-api compatible Gdb stub
# it can connect to a gdb server and interface with the lindebug frontend
# linux/x86 only
#

require 'socket'
require 'metasm'

class GdbRemoteString < Metasm::VirtualString
  attr_accessor :gdbg

  def initialize(gdbg, addr_start=0, length=0xffff_ffff)
    @gdbg = gdbg
    @pagelength = 512
    super(addr_start, length)
  end

  def dup(addr=@addr_start, len=@length)
    self.class.new(@gdbg, addr, len)
  end

  def rewrite_at(addr, data)
    len = data.length
    off = 0
    while len > @pagelength
      @gdbg.setmem(addr+off, data[off, @pagelength])
      off += @pagelength
      len -= @pagelength
    end
    @gdbg.setmem(addr+off, data[off, len])
  end

  def get_page(addr)
    @gdbg.getmem(addr, @pagelength)
  end
end

class Rubstop
  EFLAGS = {0 => 'c', 2 => 'p', 4 => 'a', 6 => 'z', 7 => 's', 9 => 'i', 10 => 'd', 11 => 'o'}
  GDBREGS = %w[eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs]	# XXX [77] = 'orig_eax'
  # define accessors for registers
  GDBREGS.compact.each { |reg|
    define_method(reg) { regs_cache[reg] }
    define_method(reg + '=') { |v| regs_cache[reg] = v ; regs_dirty }
  }

  # compute the hex checksum used in gdb protocol
  def gdb_csum(buf)
    '%02x' % (buf.unpack('C*').inject(0) { |cs, c| cs + c } & 0xff)
  end

  # send the buffer, waits ack
  # return true on success
  def gdb_send(cmd, buf='')
    buf = cmd + buf
    buf = '$' << buf << '#' << gdb_csum(buf)
    log "gdb_send(#{buf[0, 32].inspect}#{'...' if buf.length > 32})" if $DEBUG

    5.times {
      @io.write buf
      loop do
        if not IO.select([@io], nil, nil, 1)
          break
        end
        raise Errno::EPIPE if not ack = @io.read(1)
        case ack
        when '+'
          return true
        when '-'
          log "gdb_send: ack neg" if $DEBUG
          break
        when nil; return
        end
      end
    }
    log "send error #{cmd.inspect} (no ack)"
    false
  end

  # return buf, or nil on error / csum error
  def gdb_readresp
    state = :nosync
    buf = ''
    cs = ''
    while state != :done
      # XXX timeout etc
      raise Errno::EPIPE if not c = @io.read(1)
      case state
      when :nosync
        if c == '$'
          state = :data
        end
      when :data
        if c == '#'
          state = :csum1
        else
          buf << c
        end
      when :csum1
        cs << c
        state = :csum2
      when :csum2
        cs << c
        state = :done
        if cs.downcase != gdb_csum(buf).downcase
          log "transmit error"
          @io.write '-'
          return
        end
      end
    end
    @io.write '+'

    if buf =~ /^E(..)$/
      e = $1.to_i(16)
      log "error #{e} (#{Metasm::PTrace::ERRNO.index(e)})"
      return
    end
    log "gdb_readresp: got #{buf[0, 64].inspect}#{'...' if buf.length > 64}" if $DEBUG

    buf
  end

  def gdb_msg(*a)
    if gdb_send(*a)
      gdb_readresp
    end
  end

  # rle: build the regexp that will match repetitions of a character, skipping counts leading to invalid char
  rng = [3..(125-29)]
  [?+, ?-, ?#, ?$].sort.each { |invalid|
    invalid -= 29
    rng.each_with_index { |r, i|
      if r.include? invalid
        replace = [r.begin..invalid-1, invalid+1..r.end]
        replace.delete_if { |r_| r_.begin > r_.end }
        rng[i, 1] = replace
      end
    }
  }
  repet = rng.reverse.map { |r| "\\1{#{r.begin},#{r.end}}" }.join('|')
  RLE_RE = /(.)(#{repet})/

  # rle-compress a buffer
  # a character followed by '*' followed by 'x' is asc(x)-28 repetitions of the char
  # eg '0* ' => '0' * (asc(' ') - 28) = '0000'
  # for the count character, it must be 32 <= char < 126 and not be '+' '-' '#' or '$'
  def rle(buf)
    buf.gsub(RLE_RE) {
      chr, len = $1, $2.length+1
      chr + '*' + (len+28).chr
    }
  end
  # decompress rle-encoded data
  def unrle(buf) buf.gsub(/(.)\*(.)/) { $1 * ($2[0]-28) } end
  # send an integer as a long hex packed with leading 0 stripped
  def hexl(int) [int].pack('N').unpack('H*').first.gsub(/^0+(.)/, '\1') end
  # send a binary buffer as a rle hex-encoded
  def hex(buf) buf.unpack('H*').first end
  # decode an rle hex-encoded buffer
  def unhex(buf)
    buf = buf[/^[a-fA-F0-9]*/]
    buf = '0' + buf if buf.length % 1 == 1
    [buf].pack('H*')
  end

  # on-demand local cache of registers
  def regs_cache
    readregs if @regs_cache.empty?
    @regs_cache
  end

  # retrieve remote regs
  def readregs
    sync_regs
    if buf = gdb_msg('g')
      regs = unhex(unrle(buf))
      if regs.length < GDBREGS.length*4
        # retry once, was probably a response to something else
        puts "bad regs size!" if $DEBUG
        buf = gdb_msg('g')
        regs = unhex(unrle(buf)) if buf
        if not buf or regs.length < GDBREGS.length*4
          raise "regs buffer recv is too short !"
        end
      end
      @regs_dirty = false
      @regs_cache = Hash[GDBREGS.zip(regs.unpack('L*'))]
    end
    @curinstr = nil if @regs_cache['eip'] != @oldregs['eip']
  end

  # mark local cache of regs as modified, need to send it before continuing execution
  def regs_dirty
    @regs_dirty = true
  end

  # send the local copy of regs if dirty
  def sync_regs
    if not @regs_cache.empty? and @regs_dirty
      send_regs
    end
  end

  # send the local copy of regs
  def send_regs
    return if @regs_cache.empty?
    regs = @regs_cache.values_at(*GDBREGS)
    @regs_dirty = false
    gdb_msg('G', hex(regs.pack('L*')))
  end

  # read memory (small blocks prefered)
  def getmem(addr, len)
    return '' if len == 0
    if mem = gdb_msg('m', hexl(addr) << ',' << hexl(len))
      unhex(unrle(mem))
    end
  end

  # write memory (small blocks prefered)
  def setmem(addr, data)
    len = data.length
    return if len == 0
    raise 'writemem error' if not gdb_msg('M', hexl(addr) << ',' << hexl(len) << ':' << rle(hex(data)))
  end

  # read arbitrary blocks of memory (chunks to getmem)
  def [](addr, len)
    @pgm.encoded[addr, len].data rescue ''
  end

  # write arbitrary blocks of memory (chunks to getmem)
  def []=(addr, len, str)
    @pgm.encoded[addr, len] = str
  end

  def curinstr
    @curinstr ||= mnemonic_di
  end

  def mnemonic_di(addr = eip)
    @pgm.encoded.ptr = addr
    di = @pgm.cpu.decode_instruction(@pgm.encoded, addr)
    @curinstr = di if addr == @regs_cache['eip']
    di
  end

  def mnemonic(addr = eip)
    mnemonic_di(addr).instruction
  end

  def pre_run
    @oldregs = regs_cache.dup
    sync_regs
  end

  def post_run
    @regs_cache.clear
    @curinstr = nil
    @mem.invalidate
  end

  def quiet
    @quiet = true
    begin
      yield
    ensure
      @quiet = false
    end
  end

  def log_stopped(msg)
    return if @quiet ||= false
    case msg[0]
    when ?T
      sig = [msg[1, 2]].pack('H*')[0]
      misc = msg[3..-1].split(';').inject({}) { |h, s| k, v = s.split(':', 2) ; h.update k => (v || true) }
      str = "stopped by signal #{sig}"
      str = "thread #{[misc['thread']].pack('H*').unpack('N').first} #{str}" if misc['thread']
      log str
    when ?S
      sig = [msg[1, 2]].pack('H*')[0]
      log "stopped by signal #{sig}"
    end
  end

  def cont
    pre_run
    do_singlestep if @wantbp
    rmsg = gdb_msg('c')
    post_run
    ccaddr = eip-1
    if @breakpoints[ccaddr] and self[ccaddr, 1] == "\xcc"
      self[ccaddr, 1] = @breakpoints.delete ccaddr
      mem.invalidate
      self.eip = ccaddr
      @wantbp = ccaddr if not @singleshot.delete ccaddr
      sync_regs
    end
    log_stopped rmsg
  end

  def singlestep
    pre_run
    do_singlestep
    post_run
  end

  def do_singlestep
    gdb_msg('s')
    if @wantbp
      self[@wantbp, 1] = "\xcc"
      @wantbp = nil
    end
  end

  def stepover
    i = curinstr.instruction if curinstr
    if i and (i.opname == 'call' or (i.prefix and i.prefix[:rep]))
      eaddr = eip + curinstr.bin_length
      bpx eaddr, true
      quiet { cont }
    else
      singlestep
    end
  end

  def stepout
    stepover until curinstr and curinstr.opcode.name == 'ret'
    singlestep
  rescue Interrupt
    log 'interrupted'
  end

  def bpx(addr, singleshot=false)
    return if @breakpoints[addr]
    @singleshot[addr] = true if singleshot
    @breakpoints[addr] = self[addr, 1]
    self[addr, 1] = "\xcc"
  end


  def kill
    gdb_send('k')
  end

  def detach
    # TODO clear breakpoints
    gdb_send('D')
  end

  attr_accessor :pgm, :breakpoints, :singleshot, :wantbp,
    :symbols, :symbols_len, :filemap, :oldregs, :io, :mem
  def initialize(io)
    case io
    when IO; @io = io
    when /^udp:([^:]*):(\d+)$/; @io = UDPSocket.new ; @io.connect($1, $2)
    when /^(?:tcp:)?([^:]*):(\d+)$/; @io = TCPSocket.open($1, $2)
    else raise "unknown target #{io.inspect}"
    end
    @pgm = Metasm::ExeFormat.new Metasm::Ia32.new
    @mem = GdbRemoteString.new self
    @pgm.encoded = Metasm::EncodedData.new @mem
    @regs_cache = {}
    @regs_dirty = nil
    @oldregs = {}
    @breakpoints = {}
    @singleshot = {}
    @wantbp = nil
    @symbols = {}
    @symbols_len = {}
    @filemap = {}

    gdb_setup
  end

  def gdb_setup
    #gdb_msg('q', 'Supported')
    #gdb_msg('Hc', '-1')
    #gdb_msg('qC')
    if not gdb_msg('?')
      log "nobody on the line, waiting for someone to wake up"
      IO.select([@io], nil, nil, nil)
      log "who's there ?"
    end
  end

  def set_hwbp(type, addr, len=1, set=true)
    set = (set ? 'Z' : 'z')
    type = { 'r' => '3', 'w' => '2', 'x' => '1', 's' => '0' }[type] || raise("invalid hwbp type #{type}")
    gdb_msg(set, type << ',' << hexl(addr) << ',' << hexl(len))
    true
  end

  def unset_hwbp(type, addr, len=1)
    set_hwbp(type, addr, len, false)
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

  def loadsyms(baseaddr, name)
    @loadedsyms ||= {}
    return if @loadedsyms[name] or self[baseaddr, 4] != "\x7fELF"
    @loadedsyms[name] = true

    set_status " loading symbols from #{name}..."
    e = Metasm::LoadedELF.load self[baseaddr, 0x100_0000]
    e.load_address = baseaddr
    begin
      e.decode
      #e = Metasm::ELF.decode_file name rescue return         # read from disk
    rescue
      log "failed to load symbols from #{name}: #$!"
      ($!.backtrace - caller).each { |l| log l.chomp }
      @filemap[baseaddr.to_s(16)] = [baseaddr, baseaddr+0x1000]
      return
    rescue Interrupt
      log "interrupted"
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
    if e.header.type == 'EXEC' and e.header.entry >= baseaddr and e.header.entry < baseaddr + vlen
      @symbols[e.header.entry] = 'entrypoint'
    end
    set_status nil
    log "loaded #{@symbols.length-oldsyms} symbols from #{name} at #{'%08x' % baseaddr}"
  end

  # scan val at the beginning of each page (custom gdb msg)
  def pageheadsearch(val)
    resp = gdb_msg('qy', hexl(val))
    unhex(resp).unpack('L*')
  end

  def scansyms
    # TODO use qSymbol or something
    pageheadsearch("\x7fELF".unpack('L').first).each { |addr| loadsyms(addr, '%08x'%addr) }
  end

  # use qSymbol to retrieve a symbol value (uint)
  def request_symbol(name)
    resp = gdb_msg('qSymbol:', hex(name))
    if resp and a = resp.split(':')[1]
      unhex(a).unpack('N').first
    end
  end

  def loadallsyms
    # kgdb: read kernel symbols from 'module_list'
    # too bad module_list is not in ksyms
    if mod = request_symbol('module_list')
      int_at = lambda { |addr, off| @mem[addr+off, 4].unpack('L').first }
      mod_size = lambda { int_at[mod, 0] }
      mod_next = lambda { int_at[mod, 4] }
      mod_nsym = lambda { int_at[mod, 0x18] }	# most portable. yes.
      mod_syms = lambda { int_at[mod, 0x20] }

      read_strz = lambda { |addr|
        if i = @mem.index(?\0, addr)
          @mem[addr...i]
        end
      }

      while mod != 0
        symtab = [[]]

        @mem[mod_syms[], mod_nsym[]*8].to_str.unpack('L*').each { |i|
          # make a list of couples
          if symtab.last.length < 2
            symtab.last << i
          else
            symtab << [i]
          end
        }

        symtab.each { |v, n|
 					n = read_strz[n]
          # ||= to keep symbol precedence order (1st match wins)
          @symbols[v] ||= n
        }

        mod = mod_next[]
      end
    end
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

  def backtrace
    s = findsymbol(eip)
    if block_given?
      yield s
    else
      bt = []
      bt << s
    end
    fp = ebp
    while fp >= esp and fp <= esp+0x100000
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

  def checkbp ; end
end
