#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/os/main'
require 'socket'

module Metasm
# lowlevel interface to the gdbserver protocol
class GdbClient
  GDBREGS_IA32 = %w[eax ecx edx ebx esp ebp esi edi eip eflags cs ss ds es fs gs].map { |r| r.to_sym }	# XXX [77] = 'orig_eax'
  GDBREGS_X64 = %w[rax rbx rcx rdx rsi rdi rbp rsp r8 r9 r10 r11 r12 r13 r14 r15 rip rflags cs ss ds es fs gs].map { |r| r.to_sym }

  # compute the hex checksum used in gdb protocol
  def gdb_csum(buf)
    '%02x' % (buf.unpack('C*').inject(0) { |cs, c| cs + c } & 0xff)
  end

  # send the buffer, waits ack
  # return true on success
  def gdb_send(cmd, buf='')
    buf = cmd + buf
    buf = '$' << buf << '#' << gdb_csum(buf)

    5.times {
      @io.write buf
      loop do
        break if not IO.select([@io], nil, nil, 0.2)
        raise Errno::EPIPE if not ack = @io.read(1)
        case ack
        when '+'
          return true
        when '-'
          puts "gdb_send: ack neg" if $DEBUG
          break
        when nil
          return
        end
      end
    }

    log "send error #{cmd.inspect} (no ack)"
    false
  end

  def quiet_during
    pq = quiet
    @quiet = true
    yield
  ensure
    @quiet = pq
  end

  # return buf, or nil on error / csum error
  # waits IO.select(timeout) between each char
  # outstr is used internally only to handle multiline output string
  def gdb_readresp(timeout=nil, outstr=nil)
    @recv_ctx ||= {}
    @recv_ctx[:state] ||= :nosync
    buf = nil

    while @recv_ctx
      return unless IO.select([@io], nil, nil, timeout)
      raise Errno::EPIPE if not c = @io.read(1)

      case @recv_ctx[:state]
      when :nosync
        if c == '$'
          @recv_ctx[:state] = :data
          @recv_ctx[:buf] = ''
        end
      when :data
        if c == '#'
          @recv_ctx[:state] = :csum1
          @recv_ctx[:cs] = ''
        else
          @recv_ctx[:buf] << c
        end
      when :csum1
        @recv_ctx[:cs] << c
        @recv_ctx[:state] = :csum2
      when :csum2
        cs = @recv_ctx[:cs] << c
        buf = @recv_ctx[:buf]
        @recv_ctx = nil
        if cs.downcase == gdb_csum(buf).downcase
          @io.write '+'
        else
          log "transmit error"
          @io.write '-'
          return
        end
      end
    end

    case buf
    when /^E(..)$/
      e = $1.to_i(16)
      log "error #{e} (#{PTrace::ERRNO.index(e)})"
      return
    when /^O([0-9a-fA-F]*)$/
      if not outstr
        first = true
        outstr = ''
      end
      outstr << unhex($1)
      ret = gdb_readresp(timeout, outstr)
      outstr.split("\n").each { |e| log 'gdb: ' + e } if first
      return ret
    end

    puts "gdb_readresp: got #{buf[0, 64].inspect}#{'...' if buf.length > 64}" if $DEBUG
    buf
  end

  def gdb_msg(*a)
    gdb_readresp if gdb_send(*a)
  end

  # rle: build the regexp that will match repetitions of a character, skipping counts leading to invalid char
  rng = [3..(125-29)]
  [?+, ?-, ?#, ?$].sort.each { |invalid|
    invalid = invalid.unpack('C').first if invalid.kind_of? String
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
  RLE_RE = /(.)(#{repet})/m

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
  def unrle(buf) buf.gsub(/(.)\*(.)/) { $1 * ($2.unpack('C').first-28) } end
  # send an integer as a long hex packed with leading 0 stripped
  def hexl(int) @pack_netint[[int]].unpack('H*').first.sub(/^0+(.)/, '\\1') end
  # send a binary buffer as a rle hex-encoded
  def hex(buf) buf.unpack('H*').first end
  # decode an rle hex-encoded buffer
  def unhex(buf)
    buf = buf[/^[a-fA-F0-9]*/]
    buf = '0' + buf if buf.length & 1 == 1
    [buf].pack('H*')
  end

  # retrieve remote regs
  def read_regs
    if buf = gdb_msg('g')
      regs = unhex(unrle(buf))
      p @unpack_int[regs].map { |v| '%x' % v } if $DEBUG
      if regs.length < @regmsgsize
        # retry once, was probably a response to something else
        puts "bad regs size!" if $DEBUG
        buf = gdb_msg('g')
        regs = unhex(unrle(buf)) if buf
        if not buf or regs.length < @regmsgsize
          raise "regs buffer recv is too short !"
        end
      end
      Hash[*@gdbregs.zip(@unpack_int[regs]).flatten]
    end
  end

  # send the reg values
  def send_regs(r = {})
    return if r.empty?
    regs = r.values_at(*@gdbregs)
    gdb_msg('G', hex(@pack_int[regs]))
  end

  # read memory (small blocks prefered)
  def getmem(addr, len)
    return '' if len == 0
    if mem = quiet_during { gdb_msg('m', hexl(addr) << ',' << hexl(len)) } and mem != ''
      unhex(unrle(mem))
    end
  end

  # write memory (small blocks prefered)
  def setmem(addr, data)
    len = data.length
    return if len == 0
    raise 'writemem error' if not gdb_msg('M', hexl(addr) << ',' << hexl(len) << ':' << rle(hex(data)))
  end

  def continue
    gdb_send('c')
  end

  def singlestep
    gdb_send('s')
  end

  def break
    @io.write("\3")
  end

  def kill
    gdb_send('k')
  end

  def detach
    gdb_send('D')
  end

  # monitor, aka remote command
  def rcmd(cmd)
    gdb_msg('qRcmd,' + hex(cmd))
  end

  attr_accessor :io, :cpu, :gdbregs
  def initialize(io, cpu='Ia32')
    cpu = Metasm.const_get(cpu).new if cpu.kind_of? String
    raise 'unknown cpu' if not cpu.kind_of? CPU
    setup_arch(cpu)
    @cpu = cpu

    case io
    when IO; @io = io
    when /^udp:(.*):(.*?)$/i; @io = UDPSocket.new ; @io.connect($1, $2)
    when /^(?:tcp:)?(.*):(.*?)$/i; @io = TCPSocket.open($1, $2)	# XXX matches C:\fail
    # TODO pipe, serial port, etc ; also check ipv6
    else raise "unknown target #{io.inspect}"
    end

    gdb_setup
  end

  def gdb_setup
    gdb_msg('q', 'Supported')
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
    type = { 'r' => '3', 'w' => '2', 'x' => '1', 's' => '0' }[type.to_s] || raise("invalid bp type #{type.inspect}")
    gdb_msg(set, type << ',' << hexl(addr) << ',' << hexl(len))
    true
  end

  def unset_hwbp(type, addr, len=1)
    set_hwbp(type, addr, len, false)
  end

  # use qSymbol to retrieve a symbol value (uint)
  def request_symbol(name)
    resp = gdb_msg('qSymbol:', hex(name))
    if resp and a = resp.split(':')[1]
      @unpack_netint[unhex(a)].first
    end
  end

  def check_target(timeout=0)
    return if not msg = gdb_readresp(timeout)
    case msg[0]
    when ?S
      sig = unhex(msg[1, 2]).unpack('C').first
      { :state => :stopped, :info => "signal #{sig} #{PTrace::SIGNAL[sig]}" }
    when ?T
      sig = unhex(msg[1, 2]).unpack('C').first
      ret = { :state => :stopped, :info => "signal #{sig} #{PTrace::SIGNAL[sig]}" }
      ret.update msg[3..-1].split(';').inject({}) { |h, s| k, v = s.split(':', 2) ; h.update k => (v || true) }	# 'thread' -> pid
    when ?W
      code = unhex(msg[1, 2]).unpack('C').first
      { :state => :dead, :info => "exited with code #{code}" }
    when ?X
      sig = unhex(msg[1, 2]).unpack('C').first
      { :state => :dead, :info => "signal #{sig} #{PTrace::SIGNAL[sig]}" }
    else
      log "check_target: unhandled #{msg.inspect}"
      { :state => :unknown }
    end
  end

  attr_accessor :logger, :quiet
  def log(s)
    return if quiet
    @logger ||= $stdout
    @logger.puts s
  end


  # setup the various function used to pack ints & the reg list
  # according to a target CPU
  def setup_arch(cpu)
    case cpu.shortname
    when 'ia32'
      @gdbregs = GDBREGS_IA32
      @regmsgsize = 4 * @gdbregs.length
    when 'x64'
      @gdbregs = GDBREGS_X64
      @regmsgsize = 8 * @gdbregs.length
    when 'arm'
      @gdbregs = cpu.dbg_register_list
      @regmsgsize = 4 * @gdbregs.length
    else
      # we can still use readmem/kill and other generic commands
      # XXX serverside setregs may fail if we give an incorrect regbuf size
      puts "unsupported GdbServer CPU #{cpu.shortname}"
      @gdbregs = [*0..32].map { |i| "r#{i}".to_sym }
      @regmsgsize = 0
    end

    # yay life !
    # do as if cpu is littleendian, fixup at the end
    case cpu.size
    when 16
      @pack_netint   = lambda { |i| i.pack('n*') }
      @unpack_netint = lambda { |s| s.unpack('n*') }
      @pack_int   = lambda { |i| i.pack('v*') }
      @unpack_int = lambda { |s| s.unpack('v*') }
    when 32
      @pack_netint   = lambda { |i| i.pack('N*') }
      @unpack_netint = lambda { |s| s.unpack('N*') }
      @pack_int   = lambda { |i| i.pack('V*') }
      @unpack_int = lambda { |s| s.unpack('V*') }
    when 64
      bswap = lambda { |s| s.scan(/.{8}/m).map { |ss| ss.reverse }.join }
      @pack_netint   = lambda { |i| i.pack('Q*') }
      @unpack_netint = lambda { |s| s.unpack('Q*') }
      @pack_int   = lambda { |i| bswap[i.pack('Q*')] }
      @unpack_int = lambda { |s| bswap[s].unpack('Q*') }
      if [1].pack('Q')[0] == ?\1	# ruby interpreter littleendian
        @pack_netint, @pack_int = @pack_int, @pack_netint
        @unpack_netint, @unpack_int = @unpack_int, @unpack_netint
      end
    else raise "GdbServer: unsupported cpu size #{cpu.size}"
    end

    # if target cpu is bigendian, use netint everywhere
    if cpu.endianness == :big
      @pack_int   = @pack_netint
      @unpack_int = @unpack_netint
    end
  end
end

# virtual string to access the remote process memory
class GdbRemoteString < VirtualString
  attr_accessor :gdb

  def initialize(gdb, addr_start=0, length=nil)
    @gdb = gdb
    length ||= 1 << (@gdb.cpu.size rescue 32)
    @pagelength = 512
    super(addr_start, length)
  end

  def dup(addr=@addr_start, len=@length)
    self.class.new(@gdb, addr, len)
  end

  def rewrite_at(addr, data)
    len = data.length
    off = 0
    while len > @pagelength
      @gdb.setmem(addr+off, data[off, @pagelength])
      off += @pagelength
      len -= @pagelength
    end
    @gdb.setmem(addr+off, data[off, len])
  end

  def get_page(addr, len=@pagelength)
    @gdb.getmem(addr, len)
  end
end

# this class implements a high-level API using the gdb-server network debugging protocol
class GdbRemoteDebugger < Debugger
  attr_accessor :gdb, :check_target_timeout
  def initialize(url, cpu='Ia32')
    @gdb = GdbClient.new(url, cpu)
    @gdb.logger = self
    @cpu = @gdb.cpu
    @memory = GdbRemoteString.new(@gdb)
    @reg_val_cache = {}
    @regs_dirty = false
    # when checking target, if no message seen since this much seconds, send a 'status' query
    @check_target_timeout = 1
    super()
  end

  def invalidate
    sync_regs
    @reg_val_cache.clear
    super()
  end

  def get_reg_value(r)
    return @reg_val_cache[r] || 0 if @state != :stopped
    sync_regs
    @reg_val_cache = @gdb.read_regs || {} if @reg_val_cache.empty?
    @reg_val_cache[r] || 0
  end
  def set_reg_value(r, v)
    @reg_val_cache[r] = v
    @regs_dirty = true
  end

  def sync_regs
    @gdb.send_regs(@reg_val_cache) if @regs_dirty and not @reg_val_cache.empty?
    @regs_dirty = false
  end

  def do_check_target
    return if @state == :dead
    t = Time.now
    @last_check_target ||= t
    if @state == :running and t - @last_check_target > @check_target_timeout
      @gdb.io.write '$?#' << @gdb.gdb_csum('?')
      @last_check_target = t
    end
    return unless i = @gdb.check_target(0.01)
    invalidate if i[:state] == :stopped and @state != :stopped
    @state, @info = i[:state], i[:info]
    @info = nil if @info =~ /TRAP/
  end

  def do_wait_target
    return unless i = @gdb.check_target(nil)
    invalidate if i[:state] == :stopped and @state != :stopped
    @state, @info = i[:state], i[:info]
    @info = nil if @info =~ /TRAP/
  end

  def do_continue(*a)
    return if @state != :stopped
    @state = :running
    @info = 'continue'
    @gdb.continue
    @last_check_target = Time.now
  end

  def do_singlestep(*a)
    return if @state != :stopped
    @state = :running
    @info = 'singlestep'
    @gdb.singlestep
    @last_check_target = Time.now
  end

  def break
    @gdb.break
  end

  def kill(sig=nil)
    # TODO signal nr
    @gdb.kill
    @state = :dead
    @info = 'killed'
  end

  def detach
    super()	# remove breakpoints & stuff
    @gdb.detach
    @state = :dead
    @info = 'detached'
  end
  
  # set to true to use the gdb msg to handle bpx, false to set 0xcc ourself
  attr_accessor :gdb_bpx
  def enable_bp(addr)
    return if not b = @breakpoint[addr]
    b.state = :active
    case b.type
    when :bpx
      if gdb_bpx
        @gdb.set_hwbp('s', addr, 1)
      else
        @cpu.dbg_enable_bp(self, addr, b)
      end
    when :hw
      @gdb.set_hwbp(b.mtype, addr, b.mlen)
    end
  end

  def disable_bp(addr)
    return if not b = @breakpoint[addr]
    b.state = :inactive
    case b.type
    when :bpx
      if gdb_bpx
        @gdb.unset_hwbp('s', addr, 1)
      else
        @cpu.dbg_disable_bp(self, addr, b)
      end
    when :hw
      @gdb.unset_hwbp(b.mtype, addr, b.mlen)
    end
  end

  def check_pre_run(*a)
    sync_regs
    super(*a)
  end

  def loadallsyms
    puts 'loadallsyms unsupported'
  end

  def ui_command_setup(ui)
    ui.new_command('monitor', 'send a remote command to run on the target') { |arg| @gdb.rcmd(arg) }
  end
end
end
