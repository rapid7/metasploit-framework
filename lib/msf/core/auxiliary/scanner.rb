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
      OptAddressRange.new('RHOSTS', [ true, "The target address range or CIDR identifier"]),
      OptInt.new('THREADS', [ true, "The number of concurrent threads", 1 ] )
    ], Auxiliary::Scanner)

  # RHOST should not be used in scanner modules, only RHOSTS
  deregister_options('RHOST')

  register_advanced_options([
    OptBool.new('ShowProgress', [true, 'Display progress messages during a scan', true]),
    OptInt.new('ShowProgressPercent', [true, 'The interval in percent that progress should be shown', 10])
  ], Auxiliary::Scanner)

end


def check
  nmod = self.replicant
  begin
    code = nmod.check_host(datastore['RHOST'])
    return code
  rescue NoMethodError
    return Exploit::CheckCode::Unsupported
  end
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

  #
  # Sanity check threading on different platforms
  #

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

  if (self.respond_to?('run_range'))
    # No automated progress reporting for run_range
    return run_range(datastore['RHOSTS'])
  end

  if (self.respond_to?('run_host'))

    @tl = []

    while (true)
      # Spawn threads for each host
      while (@tl.length < threads_max)
        ip = ar.next_ip
        break if not ip

        @tl << framework.threads.spawn("ScannerHost(#{self.refname})-#{ip}", false, ip.dup) do |tip|
          targ = tip
          nmod = self.replicant
          nmod.datastore['RHOST'] = targ

          begin
            nmod.run_host(targ)
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

    return
  end

  if (self.respond_to?('run_batch'))

    if (! self.respond_to?('run_batch_size'))
      print_status("This module needs to export run_batch_size()")
      return
    end

    size = run_batch_size()

    ar = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])

    @tl = []

    while(true)
      nohosts = false
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

    return
  end

  print_error("This module defined no run_host, run_range or run_batch methods")

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

def scanner_progress
  return 0 unless @range_done and @range_count
  pct = (@range_done / @range_count.to_f) * 100
end

def scanner_show_progress
  pct = scanner_progress
  if(pct >= (@range_percent + @show_percent))
    @range_percent = @range_percent + @show_percent
    tdlen = @range_count.to_s.length
    print_status("Scanned #{"%.#{tdlen}d" % @range_done} of #{@range_count} hosts (#{"%.3d" % pct.to_i}% complete)")
  end
end

end
end

