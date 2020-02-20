# -*- coding: binary -*-
module Msf

###
#
# This module provides methods for scanning modules
#
###

module Auxiliary::Scanner


#
# Initializes an instance of a recon auxiliary module
#
def initialize(info = {})
  super

  register_options([
      Opt::RHOSTS,
      OptInt.new('THREADS', [ true, "The number of concurrent threads (max one per host)", 1 ] )
    ], Auxiliary::Scanner)

  register_advanced_options([
    OptBool.new('ShowProgress', [true, 'Display progress messages during a scan', true]),
    OptInt.new('ShowProgressPercent', [true, 'The interval in percent that progress should be shown', 10])
  ], Auxiliary::Scanner)

end

def has_check?
  respond_to?(:check_host)
end

def check
  nmod = replicant
  begin
    nmod.check_host(datastore['RHOST'])
  rescue NoMethodError
    Exploit::CheckCode::Unsupported
  end
end


def peer
  # IPv4 addr can be 16 chars + 1 for : and + 5 for port
  super.ljust(21)
end

#
# The command handler when launched from the console
#
def run
  @show_progress = datastore['ShowProgress']
  @show_percent  = datastore['ShowProgressPercent'].to_i

  ar             = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
  @range_count   = ar.length || 0
  @range_done    = 0
  @range_percent = 0

  threads_max = datastore['THREADS'].to_i
  @tl = []
  @scan_errors = []

  res = Queue.new
  results = Hash.new

  #
  # Sanity check threading given different conditions
  #

  if datastore['CPORT'].to_i != 0 && threads_max > 1
    print_error("Warning: A maximum of one thread is possible when a source port is set (CPORT)")
    print_error("Thread count has been adjusted to 1")
    threads_max = 1
  end

  if(Rex::Compat.is_windows)
    if(threads_max > 16)
      print_error("Warning: The Windows platform cannot reliably support more than 16 threads")
      print_error("Thread count has been adjusted to 16")
      threads_max = 16
    end
  end

  if(Rex::Compat.is_cygwin)
    if(threads_max > 200)
      print_error("Warning: The Cygwin platform cannot reliably support more than 200 threads")
      print_error("Thread count has been adjusted to 200")
      threads_max = 200
    end
  end

  begin

  if (self.respond_to?('run_host'))
    loop do
      # Stop scanning if we hit a fatal error
      break if has_fatal_errors?

      # Spawn threads for each host
      while (@tl.length < threads_max)

        # Stop scanning if we hit a fatal error
        break if has_fatal_errors?

        ip = ar.next_ip
        break if not ip

        @tl << framework.threads.spawn("ScannerHost(#{self.refname})-#{ip}", false, ip.dup) do |tip|
          targ = tip
          nmod = self.replicant
          nmod.datastore['RHOST'] = targ

          begin
            res << {tip => nmod.run_host(targ)}
          rescue ::Rex::BindFailed
            if datastore['CHOST']
              @scan_errors << "The source IP (CHOST) value of #{datastore['CHOST']} was not usable"
            end
          rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error, ::EOFError
          rescue ::Interrupt,::NoMethodError, ::RuntimeError, ::ArgumentError, ::NameError
            raise $!
          rescue ::Exception => e
            print_status("Error: #{targ}: #{e.class} #{e.message}")
            elog("Error running against host #{targ}: #{e.message}\n#{e.backtrace.join("\n")}")
          ensure
            nmod.cleanup
          end
        end
      end

      # Do as much of this work as possible while other threads are running
      while !res.empty?
        results.merge! res.pop
      end

      # Stop scanning if we hit a fatal error
      break if has_fatal_errors?

      # Exit once we run out of hosts
      if(@tl.length == 0)
        break
      end

      # Assume that the oldest thread will be one of the
      # first to finish and wait for it.  After that's
      # done, remove any finished threads from the list
      # and continue on.  This will open up at least one
      # spot for a new thread
      tla = @tl.length
      @tl.first.join
      @tl.delete_if { |t| not t.alive? }
      tlb = @tl.length

      @range_done += (tla - tlb)
      scanner_show_progress() if @show_progress
    end

    scanner_handle_fatal_errors
    return results
  end

  if (self.respond_to?('run_batch'))

    if (! self.respond_to?('run_batch_size'))
      print_status("This module needs to export run_batch_size()")
      return
    end

    size = run_batch_size()

    ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])

    while(true)
      nohosts = false

      # Stop scanning if we hit a fatal error
      break if has_fatal_errors?

      while (@tl.length < threads_max)

        batch = []

        # Create batches from each set
        while (batch.length < size)
          ip = ar.next_ip
          if (not ip)
            nohosts = true
            break
          end
          batch << ip
        end

        # Create a thread for each batch
        if (batch.length > 0)
          thread = framework.threads.spawn("ScannerBatch(#{self.refname})", false, batch) do |bat|
            nmod = self.replicant
            mybatch = bat.dup
            begin
              nmod.run_batch(mybatch)
          rescue ::Rex::BindFailed
            if datastore['CHOST']
              @scan_errors << "The source IP (CHOST) value of #{datastore['CHOST']} was not usable"
            end
            rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error
            rescue ::Interrupt,::NoMethodError, ::RuntimeError, ::ArgumentError, ::NameError
              raise $!
            rescue ::Exception => e
              print_status("Error: #{mybatch[0]}-#{mybatch[-1]}: #{e}")
            ensure
              nmod.cleanup
            end
          end
          thread[:batch_size] = batch.length
          @tl << thread
        end

        # Exit once we run out of hosts
        if (@tl.length == 0 or nohosts)
          break
        end
      end

      # Stop scanning if we hit a fatal error
      break if has_fatal_errors?

      # Exit if there are no more pending threads
      if (@tl.length == 0)
        break
      end

      # Assume that the oldest thread will be one of the
      # first to finish and wait for it.  After that's
      # done, remove any finished threads from the list
      # and continue on.  This will open up at least one
      # spot for a new thread
      tla = 0
      @tl.map {|t| tla += t[:batch_size] }
      @tl.first.join
      @tl.delete_if { |t| not t.alive? }
      tlb = 0
      @tl.map {|t| tlb += t[:batch_size] }

      @range_done += tla - tlb
      scanner_show_progress() if @show_progress
    end

    scanner_handle_fatal_errors
    return
  end

  print_error("This module defined no run_host or run_batch methods")

  rescue ::Interrupt
    print_status("Caught interrupt from the console...")
    return
  ensure
    seppuko!()
  end
end

def seppuko!
  @tl.each do |t|
    begin
      t.kill if t.alive?
    rescue ::Exception
    end
  end
end

def has_fatal_errors?
  @scan_errors && !@scan_errors.empty?
end

def scanner_handle_fatal_errors
  return unless has_fatal_errors?
  return unless @tl

  # First kill any running threads
  @tl.each {|t| t.kill if t.alive? }

  # Show the unique errors triggered by the scan
  uniq_errors = @scan_errors.uniq
  uniq_errors.each do |emsg|
    print_error("Fatal: #{emsg}")
  end
  print_error("Scan terminated due to #{uniq_errors.size} fatal error(s)")
end

def scanner_progress
  return 0 unless @range_done and @range_count
  pct = (@range_done / @range_count.to_f) * 100
end

def scanner_show_progress
  # it should already be in the process of shutting down if there are fatal errors
  return if has_fatal_errors?
  pct = scanner_progress
  if pct >= (@range_percent + @show_percent)
    @range_percent = @range_percent + @show_percent
    tdlen = @range_count.to_s.length
    print_status(sprintf("Scanned %#{tdlen}d of %d hosts (%d%% complete)", @range_done, @range_count, pct))
  end
end

def add_delay_jitter(_delay, _jitter)
  # Introduce the delay
  delay_value = _delay.to_i
  original_value = delay_value
  jitter_value = _jitter.to_i

  # Retrieve the jitter value and delay value
  # Delay = number of milliseconds to wait between each request
  # Jitter = percentage modifier. For example:
  # Delay is 1000ms (i.e. 1 second), Jitter is 50.
  # 50/100 = 0.5; 0.5*1000 = 500. Therefore, the per-request
  # delay will be 1000 +/- a maximum of 500ms.
  if delay_value > 0
    if jitter_value > 0
       rnd = Random.new
       if (rnd.rand(2) == 0)
          delay_value += rnd.rand(jitter_value)
       else
          delay_value -= rnd.rand(jitter_value)
       end
       if delay_value < 0
          delay_value = 0
       end
    end
    final_delay = delay_value.to_f / 1000.0
    vprint_status("Delaying for #{final_delay} second(s) (#{original_value}ms +/- #{jitter_value}ms)")
    sleep final_delay
  end
end

end
end

