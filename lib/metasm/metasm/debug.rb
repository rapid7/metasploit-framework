#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2006-2009 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory

module Metasm
# this class implements a high-level debugging API (abstract superclass)
class Debugger
  class Breakpoint
    attr_accessor :address,
      # context where the bp was defined
      :pid, :tid,
      # bool: oneshot ?
      :oneshot,
      # current bp state: :active, :inactive (internal use), :disabled (user-specified)
      :state,
      # type: type of breakpoint (:bpx = soft, :hwbp = hard, :bpm = memory)
      :type,
      # Expression if this is a conditionnal bp
      # may be a Proc, String or Expression, evaluated every time the breakpoint hits
      # if it returns 0 or false, the breakpoint is ignored
      :condition,
      # Proc to run if this bp has a callback
      :action,
      # Proc to run to emulate the overwritten instr behavior
      # used to avoid unset/singlestep/re-set, more multithread friendly
      # may be a DecodedInstruction for lazy initialization, see Debugger#init_bpx/has_emul_instr(bpx)
      :emul_instr,
      # internal data, cpu-specific (overwritten byte for a softbp, memory type/size for hwbp..)
      :internal,
      # reference breakpoints sharing a target implementation (same hw debug register, soft bp addr...)
      #  shared is an array of Breakpoints, the same Array object in all shared breakpoints
      #  owner is a hash key => shared (dbg.breakpoint)
      #  key is an identifier for the Bp class in owner (bp.address)
      :hash_shared, :hash_owner, :hash_key,
      # user-defined breakpoint-specific stuff
      :userdata

    # append the breakpoint to hash_owner + hash_shared
    def add(owner=@hash_owner)
      @hash_owner = owner
      @hash_key ||= @address
      return add_bpm if @type == :bpm
      if pv = owner[@hash_key]
        @hash_shared  = pv.hash_shared
        @internal   ||= pv.internal
        @emul_instr ||= pv.emul_instr
      else
        owner[@hash_key] = self
        @hash_shared = []
      end
      @hash_shared << self
    end

    # register a bpm: add references to all page start covered in @hash_owner
    def add_bpm
      m = @address + @internal[:len]
      a = @address & -0x1000
      @hash_shared = [self]

      @internal ||= {}
      @internal[:orig_prot] ||= {}
      while a < m
        if pv = @hash_owner[a]
          if not pv.hash_shared.include?(self)
            pv.hash_shared.concat @hash_shared-pv.hash_shared
            @hash_shared.each { |bpm| bpm.hash_shared = pv.hash_shared }
          end
          @internal[:orig_prot][a] = pv.internal[:orig_prot][a]
        else
          @hash_owner[a] = self
        end
        a += 0x1000
      end
    end

    # delete the breakpoint from hash_shared, and hash_owner if empty
    def del
      return del_bpm if @type == :bpm
      @hash_shared.delete self
      if @hash_shared.empty?
        @hash_owner.delete @hash_key
      elsif @hash_owner[@hash_key] == self
        @hash_owner[@hash_key] = @hash_shared.first
      end
    end

    # unregister a bpm
    def del_bpm
      m = @address + @internal[:len]
      a = @address & -0x1000
      @hash_shared.delete self
      while a < m
        pv = @hash_owner[a]
        if pv == self
          if opv = @hash_shared.find { |bpm|
              bpm.address < a + 0x1000 and bpm.address + bpm.internal[:len] > a
            }
            @hash_owner[a] = opv
          else
            @hash_owner.delete a

            # split hash_shared on disjoint ranges
            prev_shared = @hash_shared.find_all { |bpm|
              bpm.address < a + 0x1000 and bpm.address + bpm.internal[:len] <= a
            }

            prev_shared.each { |bpm|
              bpm.hash_shared = prev_shared
              @hash_shared.delete bpm
            }
          end
        end
        a += 0x1000
      end
    end
  end

  # per-process data
  attr_accessor :memory, :cpu, :disassembler, :breakpoint, :breakpoint_memory,
    :modulemap, :symbols, :symbols_len
  # per-thread data
  attr_accessor :state, :info, :breakpoint_thread, :singlestep_cb, :run_method,
    :run_args, :breakpoint_cause

  # which/where per-process/thread stuff is stored
  attr_accessor :pid_stuff, :tid_stuff, :pid_stuff_list, :tid_stuff_list

  # global debugger callbacks, called whenever such event occurs
  attr_accessor :callback_singlestep, :callback_bpx, :callback_hwbp, :callback_bpm,
    :callback_exception, :callback_newthread, :callback_endthread,
    :callback_newprocess, :callback_endprocess, :callback_loadlibrary

  # global switches, specify wether to break on exception/thread event
  #  can be a Proc that is evaluated (arg = info parameter of the evt_func)
  # trace_children is a bool to tell if we should debug subprocesses spawned
  #  by the target
  attr_accessor :pass_all_exceptions, :ignore_newthread, :ignore_endthread,
    :trace_children

  # link to the user-interface object if available
  attr_accessor :gui

  # initializes the disassembler internal data - subclasses should call super()
  def initialize
    @pid_stuff = {}
    @tid_stuff = {}
    @log_proc = nil
    @state = :dead
    @info = ''
    # stuff saved when we switch pids
    @pid_stuff_list = [:memory, :cpu, :disassembler, :symbols, :symbols_len,
      :modulemap, :breakpoint, :breakpoint_memory, :tid, :tid_stuff,
      :dead_process]
    @tid_stuff_list = [:state, :info, :breakpoint_thread, :singlestep_cb,
      :run_method, :run_args, :breakpoint_cause, :dead_thread]
    @callback_loadlibrary = lambda { |h| loadsyms(h[:address]) ; continue }
    @callback_newprocess = lambda { |h| log "process #{@pid} attached" }
    @callback_endprocess = lambda { |h| log "process #{@pid} died" }
    initialize_newpid
    initialize_newtid
  end

  def dasm; disassembler; end

  def shortname; self.class.name.split('::').last.downcase; end

  attr_reader :pid
  # change pid and associated cached data
  # this will also re-load the previously selected tid for this process
  def pid=(npid)
    return if npid == pid
    raise "invalid pid" if not check_pid(npid)
    swapout_pid
    @pid = npid
    swapin_pid
  end
  alias set_pid pid=

  attr_reader :tid
  def tid=(ntid)
    return if ntid == tid
    raise "invalid tid" if not check_tid(ntid)
    swapout_tid
    @tid = ntid
    swapin_tid
  end
  alias set_tid tid=

  # creates stuff related to a new process being debugged
  # includes disassembler, modulemap, symbols, breakpoints
  # subclasses should check that @pid maps to a real process and raise() otherwise
  # to be called with @pid/@tid set, calls initialize_memory+initialize_cpu
  def initialize_newpid
    return if not pid
    @pid_stuff_list.each { |s| instance_variable_set("@#{s}", nil) }

    @symbols = {}
    @symbols_len = {}
    @modulemap = {}
    @breakpoint = {}
    @breakpoint_memory = {}
    @tid_stuff = {}
    initialize_cpu
    initialize_memory
    initialize_disassembler
  end

  # subclasses should check that @tid maps to a real thread and raise() otherwise
  def initialize_newtid
    return if not tid
    @tid_stuff_list.each { |s| instance_variable_set("@#{s}", nil) }

    @state = :stopped
    @info = 'new'
    @breakpoint_thread = {}
    gui.swapin_tid if @disassembler and gui.respond_to?(:swapin_tid)
  end

  # initialize the disassembler from @cpu/@memory
  def initialize_disassembler
    return if not @memory or not @cpu
    @disassembler = Shellcode.decode(@memory, @cpu).disassembler
    gui.swapin_pid if gui.respond_to?(:swapin_pid)
  end

  # we're switching focus from one pid to another, save current pid data
  def swapout_pid
    return if not pid
    swapout_tid
    gui.swapout_pid if gui.respond_to?(:swapout_pid)
    @pid_stuff[@pid] ||= {}
    @pid_stuff_list.each { |fld|
      @pid_stuff[@pid][fld] = instance_variable_get("@#{fld}")
    }
  end

  # we're switching focus from one tid to another, save current tid data
  def swapout_tid
    return if not tid
    gui.swapout_tid if gui.respond_to?(:swapout_tid)
    @tid_stuff[@tid] ||= {}
    @tid_stuff_list.each { |fld|
      @tid_stuff[@tid][fld] = instance_variable_get("@#{fld}")
    }
  end

  # we're switching focus from one pid to another, load current pid data
  def swapin_pid
    return initialize_newpid if not @pid_stuff[@pid]

    @pid_stuff_list.each { |fld|
      instance_variable_set("@#{fld}", @pid_stuff[@pid][fld])
    }
    swapin_tid
    gui.swapin_pid if gui.respond_to?(:swapin_pid)
  end

  # we're switching focus from one tid to another, load current tid data
  def swapin_tid
    return initialize_newtid if not @tid_stuff[@tid]

    @tid_stuff_list.each { |fld|
      instance_variable_set("@#{fld}", @tid_stuff[@tid][fld])
    }
    gui.swapin_tid if gui.respond_to?(:swapin_tid)
  end

  # delete references to the current pid
  # switch to another pid, set @state = :dead if none available
  def del_pid
    @pid_stuff.delete @pid
    if @pid = @pid_stuff.keys.first
      swapin_pid
    else
      @state = :dead
      @info = ''
      @tid = nil
    end
  end

  # delete references to the current thread
  def del_tid
    @tid_stuff.delete @tid
    if @tid = @tid_stuff.keys.first
      swapin_tid
    else
      del_tid_notid
    end
  end

  # wipe the whole process when no TID is left
  # XXX we may have a pending evt_newthread...
  def del_tid_notid
    del_pid
  end


  # change the debugger to a specific pid/tid
  # if given a block, run the block and then restore the original pid/tid
  # pid may be an object that respond to #pid/#tid
  def switch_context(npid, ntid=nil, &b)
    if npid.respond_to?(:pid)
      ntid ||= npid.tid
      npid = npid.pid
    end
    oldpid = pid
    oldtid = tid
    set_pid npid
    set_tid ntid if ntid
    if b
      # shortcut begin..ensure overhead
      return b.call if oldpid == pid and oldtid == tid

      begin
        b.call
      ensure
        set_pid oldpid
        set_tid oldtid
      end
    end
  end
  alias set_context switch_context

  # iterate over all pids, yield in the context of this pid
  def each_pid(&b)
    # ensure @pid is last, so that we finish in the current context
    lst = @pid_stuff.keys - [@pid]
    lst << @pid
    return lst if not b
    lst.each { |p|
      set_pid p
      b.call
    }
  end

  # iterate over all tids of the current process, yield in its context
  def each_tid(&b)
    lst = @tid_stuff.keys - [@tid]
    lst << @tid
    return lst if not b
    lst.each { |t|
      set_tid t rescue next
      b.call
    }
  end

  # iterate over all tids of all pids, yield in their context
  def each_pid_tid(&b)
    each_pid { each_tid { b.call } }
  end


  # create a thread/process breakpoint
  # addr can be a numeric address, an Expression that is resolved, or
  #  a String that is parsed+resolved
  # info's keys are set to the breakpoint
  # standard keys are :type, :oneshot, :condition, :action
  # returns the Breakpoint object
  def add_bp(addr, info={})
    info[:pid] ||= @pid
    # dont define :tid for bpx, otherwise on del_bp we may switch_context to this thread that may not be stopped -> cant ptrace_write
    info[:tid] ||= @tid if info[:pid] == @pid and info[:type] == :hwbp

    b = Breakpoint.new
    info.each { |k, v|
      b.send("#{k}=", v)
    }

    switch_context(b) {
      addr = resolve_expr(addr) if not addr.kind_of? ::Integer
      b.address = addr

      b.hash_owner ||= case b.type
        when :bpm;  @breakpoint_memory
        when :hwbp; @breakpoint_thread
        when :bpx;  @breakpoint
        end
      # XXX bpm may hash_share with an :active, but be larger and still need enable()
      b.add

      enable_bp(b) if not info[:state]
    }

    b
  end

  # remove a breakpoint
  def del_bp(b)
    disable_bp(b)
    b.del
  end

  # activate an inactive breakpoint
  def enable_bp(b)
    return if b.state == :active
    if not b.hash_shared.find { |bb| bb.state == :active }
      switch_context(b) {
        if not b.internal
          init_bpx(b) if b.type == :bpx
          b.internal ||= {}
          b.hash_shared.each { |bb| bb.internal ||= b.internal }
        end
        do_enable_bp(b)
      }
    end
    b.state = :active
  end

  # deactivate an active breakpoint
  def disable_bp(b, newstate = :inactive)
    return if b.state != :active
    b.state = newstate
    return if b.hash_shared.find { |bb| bb.state == :active }
    switch_context(b) {
      do_disable_bp(b)
    }
  end


  # delete all breakpoints defined in the current thread
  def del_all_breakpoints_thread
    @breakpoint_thread.values.map { |b| b.hash_shared }.flatten.uniq.each { |b| del_bp(b) }
  end

  # delete all breakpoints for the current process and all its threads
  def del_all_breakpoints
    each_tid { del_all_breakpoints_thread }
    @breakpoint.values.map { |b| b.hash_shared }.flatten.uniq.each { |b| del_bp(b) }
    @breakpoint_memory.values.uniq.map { |b| b.hash_shared }.flatten.uniq.each { |b| del_bp(b) }
  end

  # calls do_enable_bpm for bpms, or @cpu.dbg_enable_bp
  def do_enable_bp(b)
    if b.type == :bpm; do_enable_bpm(b)
    else @cpu.dbg_enable_bp(self, b)
    end
  end

  # calls do_disable_bpm for bpms, or @cpu.dbg_disable_bp
  def do_disable_bp(b)
    if b.type == :bpm; do_disable_bpm(b)
    else @cpu.dbg_disable_bp(self, b)
    end
  end

  # called in the context of the target when a bpx is to be initialized
  # may (lazily) initialize b.emul_instr for virtual singlestep
  def init_bpx(b)
    # dont bother setting stuff up if it is never to be used
    return if b.oneshot and not b.condition

    # lazy setup of b.emul_instr: delay building emulating lambda to if/when actually needed
    # we still need to disassemble now and update @disassembler, before we patch the memory for the bpx
    di = init_bpx_disassemble(b.address)
    b.hash_shared.each { |bb| bb.emul_instr = di }
  end

  # retrieve the di at a given address, disassemble if needed
  # TODO make it so this doesn't interfere with other 'real' disassembler later commands, eg disassemble() or disassemble_fast_deep()
  # (right now, when they see the block already present they stop all processing)
  def init_bpx_disassemble(addr)
    @disassembler.disassemble_fast_block(addr)
    @disassembler.di_at(addr)
  end

  # checks if bp has an emul_instr
  # do the lazy initialization if needed
  def has_emul_instr(bp)
    if bp.emul_instr.kind_of?(DecodedInstruction)
      if di = bp.emul_instr and fdbd = @disassembler.get_fwdemu_binding(di, register_pc) and
          fdbd.all? { |k, v| (k.kind_of?(Symbol) or k.kind_of?(Indirection)) and
            k != :incomplete_binding and v != Expression::Unknown }
        # setup a lambda that will mimic, using the debugger primitives, the actual execution of the instruction
        bp.emul_instr = lambda {
          fdbd.map { |k, v|
            k = Indirection[emulinstr_resv(k.pointer), k.len] if k.kind_of?(Indirection)
            [k, emulinstr_resv(v)]
          }.each { |k, v|
            if k.to_s =~ /flags?_(.+)/i
              f = $1.downcase.to_sym
              set_flag_value(f, v)
            elsif k.kind_of?(Symbol)
              set_reg_value(k, v)
            elsif k.kind_of?(Indirection)
              memory_write_int(k.pointer, v, k.len)
            end
          }
        }
        bp.hash_shared.each { |bb| bb.emul_instr = bp.emul_instr }
      else
        bp.hash_shared.each { |bb| bb.emul_instr = nil }
      end
    end

    bp.emul_instr
  end

  def emulinstr_resv(e)
    r = e
    flags = Expression[r].externals.uniq.find_all { |f| f.to_s =~ /flags?_(.+)/i }
    if flags.first
      bd = {}
      flags.each { |f|
        f.to_s =~ /flags?_(.+)/i
        bd[f] = get_flag_value($1.downcase.to_sym)
      }
      r = r.bind(bd)
    end
    resolve(r)
  end

  # sets a breakpoint on execution
  def bpx(addr, oneshot=false, cond=nil, &action)
    h = { :type => :bpx }
    h[:oneshot] = true if oneshot
    h[:condition] = cond if cond
    h[:action] = action if action
    add_bp(addr, h)
  end

  # sets a hardware breakpoint
  # mtype in :r :w :x
  # mlen is the size of the memory zone to cover
  # mlen may be constrained by the architecture
  def hwbp(addr, mtype=:x, mlen=1, oneshot=false, cond=nil, &action)
    h = { :type => :hwbp }
    h[:hash_owner] = @breakpoint_thread
    addr = resolve_expr(addr) if not addr.kind_of? ::Integer
    mtype = mtype.to_sym
    h[:hash_key] = [addr, mtype, mlen]
    h[:internal] = { :type => mtype, :len => mlen }
    h[:oneshot] = true if oneshot
    h[:condition] = cond if cond
    h[:action] = action if action
    add_bp(addr, h)
  end

  # sets a memory breakpoint
  # mtype is :r :w :rw or :x
  # mlen is the size of the memory zone to cover
  def bpm(addr, mtype=:r, mlen=4096, oneshot=false, cond=nil, &action)
    h = { :type => :bpm }
    addr = resolve_expr(addr) if not addr.kind_of? ::Integer
    h[:hash_key] = addr & -4096	# XXX actually referenced at addr, addr+4096, ... addr+len
    h[:internal] = { :type => mtype, :len => mlen }
    h[:oneshot] = true if oneshot
    h[:condition] = cond if cond
    h[:action] = action if action
    add_bp(addr, h)
  end


  # define the lambda to use to log stuff
  def set_log_proc(l=nil, &b)
    @log_proc = l || b
  end

  # show information to the user, uses log_proc if defined
  def log(*a)
    if @log_proc
      a.each { |aa| @log_proc[aa] }
    else
      puts(*a) if $VERBOSE
    end
  end


  # marks the current cache of memory/regs invalid
  def invalidate
    @memory.invalidate if @memory
  end

  # invalidates the EncodedData backend for the dasm sections
  def dasm_invalidate
    disassembler.sections.each_value { |s| s.data.invalidate if s.data.respond_to?(:invalidate) } if disassembler
  end

  # return all breakpoints set on a specific address (or all bp)
  def all_breakpoints(addr=nil)
    ret = []
    if addr
      if b = @breakpoint[addr]
        ret |= b.hash_shared
      end
    else
      @breakpoint.each_value { |bb| ret |= bb.hash_shared }
    end

    @breakpoint_thread.each_value { |bb|
      next if addr and bb.address != addr
      ret |= bb.hash_shared
    }

    @breakpoint_memory.each_value { |bb|
      next if addr and (bb.address+bb.internal[:len] <= addr or bb.address > addr)
      ret |= bb.hash_shared
    }

    ret
  end

  # return on of the breakpoints at address addr
  def find_breakpoint(addr=nil, &b)
    return @breakpoint[addr] if @breakpoint[addr] and (not b or b.call(@breakpoint[addr]))
    all_breakpoints(addr).find { |bp| b.call bp }
  end


  # to be called right before resuming execution of the target
  # run_m is the method that should be called if the execution is stopped
  # due to a side-effect of the debugger (bpx with wrong condition etc)
  # returns nil if the execution should be avoided (just deleted the dead thread/process)
  def check_pre_run(run_m, *run_a)
    if @dead_process
      del_pid
      return
    elsif @dead_thread
      del_tid
      return
    elsif @state == :running
      return
    end
    @cpu.dbg_check_pre_run(self) if @cpu.respond_to?(:dbg_check_pre_run)
    @breakpoint_cause = nil
    @run_method = run_m
    @run_args = run_a
    @info = nil
    true
  end


  # called when the target stops due to a singlestep exception
  def evt_singlestep(b=nil)
    b ||= find_singlestep
    return evt_exception(:type => 'singlestep') if not b

    @state = :stopped
    @info = 'singlestep'
    @cpu.dbg_evt_singlestep(self) if @cpu.respond_to?(:dbg_evt_singlestep)

    callback_singlestep[] if callback_singlestep

    if cb = @singlestep_cb
      @singlestep_cb = nil
      cb.call	# call last, as the cb may change singlestep_cb/state/etc
    end
  end

  # returns true if the singlestep is due to us
  def find_singlestep
    return @cpu.dbg_find_singlestep(self) if @cpu.respond_to?(:dbg_find_singlestep)
    @run_method == :singlestep
  end

  # called when the target stops due to a soft breakpoint exception
  def evt_bpx(b=nil)
    b ||= find_bp_bpx
    # TODO handle race:
    # bpx foo ; thread hits foo ; we bc foo ; os notify us of bp hit but we already cleared everything related to 'bpx foo' -> unhandled bp exception
    return evt_exception(:type => 'breakpoint') if not b

    @state = :stopped
    @info = 'breakpoint'
    @cpu.dbg_evt_bpx(self, b) if @cpu.respond_to?(:dbg_evt_bpx)

    callback_bpx[b] if callback_bpx

    post_evt_bp(b)
  end

  # return the breakpoint that is responsible for the evt_bpx
  def find_bp_bpx
    return @cpu.dbg_find_bpx(self) if @cpu.respond_to?(:dbg_find_bpx)
    @breakpoint[pc]
  end

  # called when the target stops due to a hwbp exception
  def evt_hwbp(b=nil)
    b ||= find_bp_hwbp
    return evt_exception(:type => 'hwbp') if not b

    @state = :stopped
    @info = 'hwbp'
    @cpu.dbg_evt_hwbp(self, b) if @cpu.respond_to?(:dbg_evt_hwbp)

    callback_hwbp[b] if callback_hwbp

    post_evt_bp(b)
  end

  # return the breakpoint that is responsible for the evt_hwbp
  def find_bp_hwbp
    return @cpu.dbg_find_hwbp(self) if @cpu.respond_to?(:dbg_find_hwbp)
    @breakpoint_thread.find { |b| b.address == pc }
  end

  # called for archs where the same interrupt is generated for hwbp and singlestep
  # checks if a hwbp matches, then call evt_hwbp, else call evt_singlestep (which
  # will forward to evt_exception if singlestep does not match either)
  def evt_hwbp_singlestep
    if b = find_bp_hwbp
      evt_hwbp(b)
    else
      evt_singlestep
    end
  end

  # called when the target stops due to a memory exception caused by a memory bp
  # called by evt_exception
  def evt_bpm(b)
    @state = :stopped
    @info = 'bpm'

    callback_bpm[b] if callback_bpm

    post_evt_bp(b)
  end

  # return a bpm whose page coverage includes the fault described in info
  def find_bp_bpm(info)
    @breakpoint_memory[info[:fault_addr] & -0x1000]
  end

  # returns true if the fault described in info is valid to trigger b
  def check_bpm_range(b, info)
    return if b.address+b.internal[:len] <= info[:fault_addr]
    return if b.address >= info[:fault_addr] + info[:fault_len]
    case b.internal[:type]
    when :r; info[:fault_access] == :r	# or info[:fault_access] == :x
    when :w; info[:fault_access] == :w
    when :x; info[:fault_access] == :x	# XXX non-NX cpu => check pc is in bpm range ?
    when :rw; true
    end
  end

  # handles breakpoint conditions/callbacks etc
  def post_evt_bp(b)
    @breakpoint_cause = b

    found_valid_active = false

    pre_callback_pc = pc

    # XXX may have many active bps with callback that continue/singlestep/singlestep{}...
    b.hash_shared.dup.find_all { |bb|
      # ignore inactive bps
      next if bb.state != :active

      # ignore out-of-range bpms
      next if bb.type == :bpm and not check_bpm_range(bb, b.internal)

      # check condition
      case bb.condition
      when nil; cd = 1
      when Proc; cd = bb.condition.call
      when String, Expression; cd = resolve_expr(bb.condition)
      else raise "unknown bp condition #{bb.condition.inspect}"
      end
      next if not cd or cd == 0

      found_valid_active = true

      # oneshot
      del_bp(bb) if bb.oneshot

      bb.action
    }.each { |bb| bb.action.call }

    # discard @breakpoint_cause if a bp callback did modify register_pc
    @breakpoint_cause = nil if pc != pre_callback_pc

    # we did break due to a bp whose condition is not true: resume
    # (unless a callback already resumed)
    resume_badbreak(b) if not found_valid_active and @state == :stopped
  end

  # called whenever the target stops due to an exception
  # type may be:
  # * 'access violation', :fault_addr, :fault_len, :fault_access (:r/:w/:x)
  # anything else for other exceptions (access violation is special to handle bpm)
  # ...
  def evt_exception(info={})
    if info[:type] == 'access violation' and b = find_bp_bpm(info)
      info[:fault_len] ||= 1
      b.internal.update info
      return evt_bpm(b)
    end

    @state = :stopped
    @info = "exception #{info[:type]}"

    callback_exception[info] if callback_exception

    pass = pass_all_exceptions
    pass = pass[info] if pass.kind_of? Proc
    if pass
      pass_current_exception
      resume_badbreak
    end
  end

  def evt_newthread(info={})
    @state = :stopped
    @info = 'new thread'

    callback_newthread[info] if callback_newthread

    ign = ignore_newthread
    ign = ign[info] if ign.kind_of? Proc
    if ign
      continue
    end
  end

  def evt_endthread(info={})
    @state = :stopped
    @info = 'end thread'
    # mark the thread as to be deleted on next check_pre_run
    @dead_thread = true

    callback_endthread[info] if callback_endthread

    ign = ignore_endthread
    ign = ign[info] if ign.kind_of? Proc
    if ign
      continue
    end
  end

  def evt_newprocess(info={})
    @state = :stopped
    @info = 'new process'

    callback_newprocess[info] if callback_newprocess
  end

  def evt_endprocess(info={})
    @state = :stopped
    @info = 'end process'
    @dead_process = true

    callback_endprocess[info] if callback_endprocess
  end

  def evt_loadlibrary(info={})
    @state = :stopped
    @info = 'loadlibrary'

    callback_loadlibrary[info] if callback_loadlibrary
  end

  # called when we did break due to a breakpoint whose condition is invalid
  # resume execution as if we never stopped
  # disable offending bp + singlestep if needed
  def resume_badbreak(b=nil)
    # ensure we didn't delete b
    if b and b.hash_shared.find { |bb| bb.state == :active }
      rm = @run_method
      if rm == :singlestep
        singlestep_bp(b)
      else
        ra = @run_args
        singlestep_bp(b) { send rm, *ra }
      end
    else
      send @run_method, *@run_args
    end
  end

  # singlesteps over an active breakpoint and run its block
  # if the breakpoint provides an emulation stub, run that, otherwise
  # disable the breakpoint, singlestep, and re-enable
  def singlestep_bp(bp, &b)
    if has_emul_instr(bp)
      @state = :stopped
      bp.emul_instr.call
      b.call if b
    else
      bp.hash_shared.each { |bb|
        disable_bp(bb, :temp_inactive) if bb.state == :active
      }
      # this *should* work with different bps stopping the current instr
      prev_sscb = @singlestep_cb
      singlestep {
        bp.hash_shared.each { |bb|
          enable_bp(bb) if bb.state == :temp_inactive
        }
        prev_sscb[] if prev_sscb
        b.call if b
      }
    end
  end

  # checks if @breakpoint_cause is valid, or was obsoleted by the user changing pc
  def check_breakpoint_cause
    if bp = @breakpoint_cause and
        (bp.type == :bpx or (bp.type == :hwbp and bp.internal[:type] == :x)) and
        pc != bp.address
      bp = @breakpoint_cause = nil
    end
    bp
  end

  # checks if the running target has stopped (nonblocking)
  # returns false if no debug event happened
  def check_target
    do_check_target
  end

  # waits until the running target stops (due to a breakpoint, fault, etc)
  def wait_target
    do_wait_target while @state == :running
  end

  # resume execution of the target
  # bypasses a software breakpoint on pc if needed
  # thread breakpoints must be manually disabled before calling continue
  def continue
    if b = check_breakpoint_cause and b.hash_shared.find { |bb| bb.state == :active }
      singlestep_bp(b) {
        next if not check_pre_run(:continue)
        do_continue
      }
    else
      return if not check_pre_run(:continue)
      do_continue
    end
  end
  alias run continue

  # continue ; wait_target
  def continue_wait
    continue
    wait_target
  end

  # resume execution of the target one instruction at a time
  def singlestep(&b)
    @singlestep_cb = b
    bp = check_breakpoint_cause
    return if not check_pre_run(:singlestep)
    if bp and bp.hash_shared.find { |bb| bb.state == :active } and has_emul_instr(bp)
      @state = :stopped
      bp.emul_instr.call
      invalidate
      evt_singlestep(true)
    else
      do_singlestep
    end
  end

  # singlestep ; wait_target
  def singlestep_wait(&b)
    singlestep(&b)
    wait_target
  end

  # tests if the specified instructions should be stepover() using singlestep or
  # by putting a breakpoint at next_addr
  def need_stepover(di = di_at(pc))
    di and @cpu.dbg_need_stepover(self, di.address, di)
  end

  # stepover: singlesteps, but do not enter in subfunctions
  def stepover
    di = di_at(pc)
    if need_stepover(di)
      bpx di.next_addr, true, Expression[:tid, :==, @tid]
      continue
    else
      singlestep
    end
  end

  # stepover ; wait_target
  def stepover_wait
    stepover
    wait_target
  end

  # checks if an instruction should stop the stepout() (eg it is a return instruction)
  def end_stepout(di = di_at(pc))
    di and @cpu.dbg_end_stepout(self, di.address, di)
  end

  # stepover until finding the last instruction of the function
  def stepout
    # TODO thread-local bps
    while not end_stepout
      stepover
      wait_target
    end
    do_singlestep
  end

  def stepout_wait
    stepout
    wait_target
  end

  # set a singleshot breakpoint, run the process, and wait
  def go(target, cond=nil)
    bpx(target, true, cond)
    continue_wait
  end

  # continue_wait until @state == :dead
  def run_forever
    continue_wait until @state == :dead
  end

  # decode the Instruction at the address, use the @disassembler cache if available
  def di_at(addr)
    @disassembler.di_at(addr) || @disassembler.disassemble_instruction(addr)
  end

  # list the general purpose register names available for the target
  def register_list
    @cpu.dbg_register_list
  end

  # hash { register_name => register_size_in_bits }
  def register_size
    @cpu.dbg_register_size
  end

  # retrieves the name of the register holding the program counter (address of the next instruction)
  def register_pc
    @cpu.dbg_register_pc
  end

  # retrieve the name of the register holding the stack pointer
  def register_sp
    @cpu.dbg_register_sp
  end

  # then name of the register holding the cpu flags
  def register_flags
    @cpu.dbg_register_flags
  end

  # list of flags available in the flag register
  def flag_list
    @cpu.dbg_flag_list
  end

  # retreive the value of the program counter register (eip)
  def pc
    get_reg_value(register_pc)
  end
  alias ip pc

  # change the value of pc
  def pc=(v)
    set_reg_value(register_pc, v)
  end
  alias ip= pc=

  # retrieve the value of the stack pointer register
  def sp
    get_reg_value(register_sp)
  end

  # update the stack pointer
  def sp=(v)
    set_reg_value(register_sp, v)
  end

  # retrieve the value of a flag (0/1)
  def get_flag_value(f)
    @cpu.dbg_get_flag(self, f)
  end

  # retrieve the value of a flag (true/false)
  def get_flag(f)
    get_flag_value(f) != 0
  end

  # change the value of a flag
  def set_flag_value(f, v)
    (v && v != 0) ? set_flag(f) : unset_flag(f)
  end

  # switch the value of a flag (true->false, false->true)
  def toggle_flag(f)
    set_flag_value(f, 1-get_flag_value(f))
  end

  # set the value of the flag to true
  def set_flag(f)
    @cpu.dbg_set_flag(self, f)
  end

  # set the value of the flag to false
  def unset_flag(f)
    @cpu.dbg_unset_flag(self, f)
  end

  # returns the name of the module containing addr or nil
  def addr2module(addr)
    @modulemap.keys.find { |k| @modulemap[k][0] <= addr and @modulemap[k][1] > addr }
  end

  # returns a string describing addr in term of symbol (eg 'libc.so.6!printf+2f')
  def addrname(addr)
    (addr2module(addr) || '???') + '!' +
    if s = @symbols[addr] ? addr : @symbols_len.keys.find { |s_| s_ < addr and s_ + @symbols_len[s_] > addr }
      @symbols[s] + (addr == s ? '' : ('+%x' % (addr-s)))
    else '%08x' % addr
    end
  end

  # same as addrname, but scan preceding addresses if no symbol matches
  def addrname!(addr)
    (addr2module(addr) || '???') + '!' +
    if s = @symbols[addr] ? addr :
        @symbols_len.keys.find { |s_| s_ < addr and s_ + @symbols_len[s_] > addr } ||
        @symbols.keys.sort.find_all { |s_| s_ < addr and s_ + 0x10000 > addr }.max
      @symbols[s] + (addr == s ? '' : ('+%x' % (addr-s)))
    else '%08x' % addr
    end
  end

  # loads the symbols from a mapped module
  def loadsyms(addr, name='%08x'%addr.to_i)
    if addr.kind_of? String
      modules.each { |m|
        if m.path =~ /#{addr}/i
          addr = m.addr
          name = File.basename m.path
          break
        end
      }
      return if not addr.kind_of? Integer
    end
    return if not peek = @memory.get_page(addr, 4)
    if peek == "\x7fELF"
      cls = LoadedELF
    elsif peek[0, 2] == "MZ" and @memory[addr+@memory[addr+0x3c,4].unpack('V').first, 4] == "PE\0\0"
      cls = LoadedPE
    else return
    end

    begin
      e = cls.load @memory[addr, 0x1000_0000]
      e.load_address = addr
      e.decode_header
      e.decode_exports
    rescue
      # cache the error so that we dont hit it every time
      @modulemap[addr.to_s(16)] ||= [addr, addr+0x1000]
      return
    end

    if n = e.module_name and n != name
      name = n
    end

    @modulemap[name] ||= [addr, addr+e.module_size]

    cnt = 0
    e.module_symbols.each { |n_, a, l|
      cnt += 1
      a += addr
      @disassembler.set_label_at(a, n_, false)
      @symbols[a] = n_	# XXX store "lib!sym" ?
      if l and l > 1; @symbols_len[a] = l
      else @symbols_len.delete a	# we may overwrite an existing symbol, keep len in sync
      end
    }
    log "loaded #{cnt} symbols from #{name}"

    true
  end

  # scan the target memory for loaded libraries, load their symbols
  def scansyms(addr=0, max=@memory.length-0x1000-addr)
    while addr <= max
      loadsyms(addr)
      addr += 0x1000
    end
  end

  # load symbols from all libraries found by the OS module
  def loadallsyms(&b)
    modules.each { |m|
      b.call(m.addr) if b
      loadsyms(m.addr, m.path)
    }
  end

  # see Disassembler#load_map
  def load_map(str, off=0)
    str = File.read(str) if File.exist?(str)
    sks = @disassembler.sections.keys.sort
    str.each_line { |l|
      case l.strip
      when /^([0-9A-F]+)\s+(\w+)\s+(\w+)/i    # kernel.map style
        a = $1.to_i(16) + off
        n = $3
      when /^([0-9A-F]+):([0-9A-F]+)\s+([a-z_]\w+)/i  # IDA style
        # see Disassembler for comments
        a = sks[$1.to_i(16)] + $2.to_i(16) + off
        n = $3
      else next
      end
      @disassembler.set_label_at(a, n, false)
      @symbols[a] = n
    }

  end

  # parses the expression contained in arg
  def parse_expr(arg)
    parse_expr!(arg.dup)
  end

  # parses the expression contained in arg, updates arg to point after the expr
  def parse_expr!(arg, &b)
    return if not e = IndExpression.parse_string!(arg) { |s|
      # handle 400000 -> 0x400000
      # XXX no way to override and force decimal interpretation..
      if s.length > 4 and not @disassembler.get_section_at(s.to_i) and @disassembler.get_section_at(s.to_i(16))
        s.to_i(16)
      else
        s.to_i
      end
    }

    # resolve ambiguous symbol names/hex values
    bd = {}
    e.externals.grep(::String).each { |ex|
      if not v = register_list.find { |r| ex.downcase == r.to_s.downcase } ||
            (b && b.call(ex)) || symbols.index(ex)
        lst = symbols.values.find_all { |s| s.downcase.include? ex.downcase }
        case lst.length
        when 0
          if ex =~ /^[0-9a-f]+$/i and @disassembler.get_section_at(ex.to_i(16))
            v = ex.to_i(16)
          else
            raise "unknown symbol name #{ex}"
          end
        when 1
          v = symbols.index(lst.first)
          log "using #{lst.first} for #{ex}"
        else
          suggest = lst[0, 50].join(', ')
          suggest = suggest[0, 125] + '...' if suggest.length > 128
          raise "ambiguous symbol name #{ex}: #{suggest} ?"
        end
      end
      bd[ex] = v
    }
    e = e.bind(bd)

    e
  end

  # resolves an expression involving register values and/or memory indirection using the current context
  # uses #register_list, #get_reg_value, @mem, @cpu
  # :tid/:pid resolve to current thread
  def resolve_expr(e)
    e = parse_expr(e) if e.kind_of? ::String
    bd = { :tid => @tid, :pid => @pid }
    Expression[e].externals.each { |ex|
      next if bd[ex]
      case ex
      when ::Symbol; bd[ex] = get_reg_value(ex)
      when ::String; bd[ex] = @symbols.index(ex) || @disassembler.prog_binding[ex] || 0
      end
    }
    Expression[e].bind(bd).reduce { |i|
      if i.kind_of? Indirection and p = i.pointer.reduce and p.kind_of? ::Integer
        i.len ||= @cpu.size/8
        p &= (1 << @cpu.size) - 1 if p < 0
        Expression.decode_imm(@memory, i.len, @cpu, p)
      end
    }
  end
  alias resolve resolve_expr

  # return/yield an array of [addr, addr symbolic name] corresponding to the current stack trace
  def stacktrace(maxdepth=500, &b)
    @cpu.dbg_stacktrace(self, maxdepth, &b)
  end

  # accepts a range or begin/end address to read memory, or a register name
  def [](arg0, arg1=nil)
    if arg1
      arg0 = resolve_expr(arg0) if not arg0.kind_of? ::Integer
      arg1 = resolve_expr(arg1) if not arg1.kind_of? ::Integer
      @memory[arg0, arg1].to_str
    elsif arg0.kind_of? ::Range
      arg0.begin = resolve_expr(arg0.begin) if not arg0.begin.kind_of? ::Integer	# cannot happen, invalid ruby Range
      arg0.end = resolve_expr(arg0.end) if not arg0.end.kind_of? ::Integer
      @memory[arg0].to_str
    else
      get_reg_value(arg0)
    end
  end

  # accepts a range or begin/end address to write memory, or a register name
  def []=(arg0, arg1, val=nil)
    arg1, val = val, arg1 if not val
    if arg1
      arg0 = resolve_expr(arg0) if not arg0.kind_of? ::Integer
      arg1 = resolve_expr(arg1) if not arg1.kind_of? ::Integer
      @memory[arg0, arg1] = val
    elsif arg0.kind_of? ::Range
      arg0.begin = resolve_expr(arg0.begin) if not arg0.begin.kind_of? ::Integer	# cannot happen, invalid ruby Range
      arg0.end = resolve_expr(arg0.end) if not arg0.end.kind_of? ::Integer
      @memory[arg0] = val
    else
      set_reg_value(arg0, val)
    end
  end


  # read an int from the target memory, int of sz bytes (defaults to cpu.size)
  def memory_read_int(addr, sz=@cpu.size/8)
    addr = resolve_expr(addr) if not addr.kind_of? ::Integer
    Expression.decode_imm(@memory, sz, @cpu, addr)
  end

  # write an int in the target memory
  def memory_write_int(addr, val, sz=@cpu.size/8)
    addr = resolve_expr(addr) if not addr.kind_of? ::Integer
    val = resolve_expr(val) if not val.kind_of? ::Integer
    @memory[addr, sz] = Expression.encode_imm(val, sz, @cpu)
  end

  # retrieve an argument (call at a function entrypoint)
  def func_arg(nr)
    @cpu.dbg_func_arg(self, nr)
  end
  def func_arg_set(nr, val)
    @cpu.dbg_func_arg_set(self, nr, val)
  end

  # retrieve a function returned value (call at func exitpoint)
  def func_retval
    @cpu.dbg_func_retval(self)
  end
  def func_retval_set(val)
    @cpu.dbg_func_retval_set(self, val)
  end
  def func_retval=(val)
    @cpu.dbg_func_retval_set(self, val)
  end

  # retrieve a function return address (call at func entry/exit)
  def func_retaddr
    @cpu.dbg_func_retaddr(self)
  end
  def func_retaddr_set(addr)
    @cpu.dbg_func_retaddr_set(self, addr)
  end
  def func_retaddr=(addr)
    @cpu.dbg_func_retaddr_set(self, addr)
  end

  def load_plugin(plugin_filename)
    if not File.exist?(plugin_filename) and defined? Metasmdir
      # try autocomplete
      pf = File.join(Metasmdir, 'samples', 'dbg-plugins', plugin_filename)
      if File.exist?(pf)
        plugin_filename = pf
      elsif File.exist?(pf + '.rb')
        plugin_filename = pf + '.rb'
      end
    end
    if (not File.exist?(plugin_filename) or File.directory?(plugin_filename)) and File.exist?(plugin_filename + '.rb')
      plugin_filename += '.rb'
    end

    instance_eval File.read(plugin_filename)
  end

  # return the list of memory mappings of the current process
  # array of [start, len, perms, infos]
  def mappings
    [[0, @memory.length]]
  end

  # return a list of Process::Modules (with a #path, #addr) for the current process
  def modules
    []
  end

  # list debugged pids
  def list_debug_pids
    @pid_stuff.keys | [@pid].compact
  end

  # return a list of OS::Process listing all alive processes (incl not debugged)
  # default version only includes current debugged pids
  def list_processes
    list_debug_pids.map { |p| OS::Process.new(p) }
  end

  # check if pid is valid
  def check_pid(pid)
    list_processes.find { |p| p.pid == pid }
  end

  # list debugged tids
  def list_debug_tids
    @tid_stuff.keys | [@tid].compact
  end

  # list of thread ids existing in the current process (incl not debugged)
  # default version only lists debugged tids
  alias list_threads list_debug_tids

  # check if tid is valid for the current process
  def check_tid(tid)
    list_threads.include?(tid)
  end

  # see EData#pattern_scan
  # scans only mapped areas of @memory, using os_process.mappings
  def pattern_scan(pat, start=0, len=@memory.length-start, &b)
    ret = []
    mappings.each { |maddr, mlen, perm, *o_|
      next if perm !~ /r/i
      mlen -= start-maddr if maddr < start
      maddr = start if maddr < start
      mlen = start+len-maddr if maddr+mlen > start+len
      next if mlen <= 0
      EncodedData.new(read_mapped_range(maddr, mlen)).pattern_scan(pat) { |off|
        off += maddr
        ret << off if not b or b.call(off)
      }
    }
    ret
  end

  def read_mapped_range(addr, len)
    # try to use a single get_page call
    s = @memory.get_page(addr, len) || ''
    s.length == len ? s : (s = @memory[addr, len] ? s.to_str : nil)
  end
end
end
