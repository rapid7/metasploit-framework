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

      register_options(
        [
          Opt::RHOSTS,
          OptInt.new('THREADS', [true, "The number of concurrent threads", 1])
        ], Auxiliary::Scanner
      )

      register_advanced_options(
        [
          OptBool.new('ShowProgress', [true, 'Display progress messages during a scan', true]),
          OptInt.new('ShowProgressPercent', [true, 'The interval in percent that progress should be shown', 10])
        ], Auxiliary::Scanner
      )
    end

    def peer
      # IPv4 addr can be 16 chars + 1 for : and + 5 for port
      super.ljust(21)
    end

    def add_delay_jitter(delay_value, jitter_value)
      # Introduce the delay
      delay_value = delay_value.to_i
      original_value = delay_value
      jitter_value = jitter_value.to_i

      # Retrieve the jitter value and delay value
      # Delay = number of milliseconds to wait between each request
      # Jitter = percentage modifier. For example:
      # Delay is 1000ms (i.e. 1 second), Jitter is 50.
      # 50/100 = 0.5; 0.5*1000 = 500. Therefore, the per-request
      # delay will be 1000 +/- a maximum of 500ms.
      if delay_value > 0
        if jitter_value > 0
          rnd = Random.new
          if rnd.rand(2) == 0
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

    def cleanup_threads!
      @tl.each do |t|
        begin
          t.kill if t.alive?
        rescue StandardError
        end
      end
    end

    def run_scanner(method)
      size = respond_to?('run_batch_size') ? run_batch_size : 1

      loop do
        no_more_hosts = false

        # Stop scanning if we hit a fatal error
        break if fatal_errors?

        while @tl.length < @threads_max

          batch = []

          # Create batches from each set
          while batch.length < size
            ip = @ar.next_ip
            if !ip
              no_more_hosts = true
              break
            end
            batch << ip
          end

          # Create a thread for each batch
          if batch.length > 0
            thread = framework.threads.spawn("ScannerBatch(#{refname})", false, batch) do |batch|
              nmod = replicant
              begin
                if method == 'run_batch'
                  nmod.run_batch(batch)
                else
                  nmod.datastore['RHOST'] = batch[0]
                  nmod.public_send(method, batch[0])
                end
              rescue Rex::ConnectionError, Rex::ConnectionProxyError, Errno::ECONNRESET, Errno::EINTR, Rex::TimeoutError, Timeout::Error
              rescue Rex::BindFailed
                if datastore['CHOST']
                  @scan_errors << "The source IP (CHOST) value of #{datastore['CHOST']} was not usable"
                end
              rescue Interrupt, NoMethodError, RuntimeError, ArgumentError, NameError
                raise $ERROR_INFO
              rescue StandardError => e
                if size == 1
                  print_status("Error: #{batch[0]}: #{e.class} #{e.message}")
                else
                  print_status("Error: #{batch[0]} - #{batch[-1]}: #{e.class} #{e.message}")
                end
                elog("Error running against host(s) #{batch}: #{e.message}\n#{e.backtrace.join("\n")}")
              ensure
                nmod.cleanup
              end
            end
            thread[:batch_size] = batch.length
            @tl << thread
          end

          # Exit once we run out of hosts
          if @tl.length == 0 || no_more_hosts
            break
          end
        end

        # Stop scanning if we hit a fatal error
        break if fatal_errors?

        # Exit if there are no more pending threads
        if @tl.length == 0
          break
        end

        # Assume that the oldest thread will be one of the
        # first to finish and wait for it.  After that's
        # done, remove any finished threads from the list
        # and continue on.  This will open up at least one
        # spot for a new thread
        tla = 0
        @tl.map { |t| tla += t[:batch_size] }
        @tl.first.join
        @tl.delete_if { |t| !t.alive? }
        tlb = 0
        @tl.map { |t| tlb += t[:batch_size] }

        @range_done += tla - tlb
        scanner_show_progress if @show_progress
      end

      scanner_handle_fatal_errors
    end

    def start_scanner(method)
      @show_progress = datastore['ShowProgress']
      @show_percent  = datastore['ShowProgressPercent'].to_i

      @ar            = Rex::Socket::RangeWalker.new(datastore['RHOSTS'])
      @range_count   = @ar.length || 0
      @range_done    = 0
      @range_percent = 0

      @threads_max = datastore['THREADS'].to_i
      @tl = []
      @scan_errors = []

      #
      # Sanity check threading given different conditions
      #

      if datastore['CPORT'].to_i != 0 && @threads_max > 1
        print_error("Warning: A maximum of one thread is possible when a source port is set (CPORT)")
        print_error("Thread count has been adjusted to 1")
        @threads_max = 1
      end

      if method == 'check'
        run_scanner('check_host')
      elsif respond_to?('run_batch')
        run_scanner('run_batch')
      elsif respond_to?('run_host')
        run_scanner('run_host')
      else
        print_error("This module defined no run_host or run_batch methods")
        return
      end
    rescue Interrupt
      print_status("Caught interrupt from the console...")
    ensure
      cleanup_threads!
    end

    def check
      start_scanner('check')
    rescue NoMethodError
      Exploit::CheckCode::Unsupported
    end

    #
    # The command handler when launched from the console
    #
    def run
      start_scanner('run')
    end

    def fatal_errors?
      @scan_errors && !@scan_errors.empty?
    end

    def scanner_handle_fatal_errors
      return unless fatal_errors?
      return unless @tl

      # First kill any running threads
      @tl.each { |t| t.kill if t.alive? }

      # Show the unique errors triggered by the scan
      uniq_errors = @scan_errors.uniq
      uniq_errors.each do |emsg|
        print_error("Fatal: #{emsg}")
      end
      print_error("Scan terminated due to #{uniq_errors.size} fatal error(s)")
    end

    def scanner_progress
      return 0 unless @range_done && @range_count
      (@range_done / @range_count.to_f) * 100
    end

    def scanner_show_progress
      # it should already be in the process of shutting down if there are fatal errors
      return if fatal_errors?
      pct = scanner_progress
      if pct >= (@range_percent + @show_percent)
        @range_percent += @show_percent
        tdlen = @range_count.to_s.length
        print_status("Scanned #{@range_done} of #{@range_count} hosts (#{pct}% complete)")
      end
    end
  end
end
