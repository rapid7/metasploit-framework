# -*- coding: binary -*-

module Msf
module Ui
module Console

###
#
# Module-specific command dispatcher.
#
###
module ModuleCommandDispatcher

  include Msf::Ui::Console::CommandDispatcher
  include Msf::Ui::Console::ModuleArgumentParsing

  def commands
    {
      "reload" => "Reload the current module from disk",
      "check"  => "Check to see if a target is vulnerable"
    }
  end

  #
  # The active driver module, if any.
  #
  def mod
    return driver.active_module
  end

  #
  # Sets the active driver module.
  #
  def mod=(m)
    self.driver.active_module = m
  end

  def check_progress
    return 0 unless @range_done and @range_count
    pct = (@range_done / @range_count.to_f) * 100
  end

  def check_show_progress
    pct = check_progress
    if(pct >= (@range_percent + @show_percent))
      @range_percent = @range_percent + @show_percent
      tdlen = @range_count.to_s.length
      print_status("Checked #{"%.#{tdlen}d" % @range_done} of #{@range_count} hosts (#{"%.3d" % pct.to_i}% complete)")
    end
  end

  def check_multiple(mod)
    rhosts_walker = Msf::RhostsWalker.new(mod.datastore['RHOSTS'], mod.datastore).to_enum
    rhosts_walker_count = rhosts_walker.count

    # Short-circuit check_multiple if it's a single host, or doesn't have any hosts set
    if rhosts_walker_count <= 1
      nmod = mod.replicant
      nmod.datastore.merge!(rhosts_walker.next) if rhosts_walker_count == 1
      check_simple(nmod)
      return
    end

    # This part of the code is mostly from scanner.rb
    @show_progress = framework.datastore['ShowProgress'] || mod.datastore['ShowProgress'] || false
    @show_percent  = ( framework.datastore['ShowProgressPercent'] || mod.datastore['ShowProgressPercent'] ).to_i

    @range_count   = rhosts_walker_count || 0
    @range_done    = 0
    @range_percent = 0

    # Set the default thread to 1. The same behavior as before.
    threads_max = (framework.datastore['THREADS'] || mod.datastore['THREADS'] || 1).to_i
    @tl = []

    if Rex::Compat.is_windows
      if threads_max > 16
        print_warning("Thread count has been adjusted to 16")
        threads_max = 16
      end
    end

    if Rex::Compat.is_cygwin
      if threads_max > 200
        print_warning("Thread count has been adjusted to 200")
        threads_max = 200
      end
    end

    loop do
      while @tl.length < threads_max
        begin
          datastore = rhosts_walker.next
        rescue StopIteration
          datastore = nil
        end
        break unless datastore

        @tl << framework.threads.spawn("CheckHost-#{datastore['RHOSTS']}", false, datastore.dup) { |thr_datastore|
          # Make sure this is thread-safe when assigning an IP to the RHOST
          # datastore option
          nmod = mod.replicant
          nmod.datastore.merge!(thr_datastore)
          Msf::Simple::Framework.simplify_module(nmod)
          check_simple(nmod)
        }
      end

      break if @tl.length == 0

      tla = @tl.length

      # This exception handling is necessary, the first thread with errors can kill the
      # whole check_multiple and leave the rest of the threads running in background and
      # only accessible with the threads command (Thread.list)
      begin
        @tl.first.join
      rescue ::Exception => exception
        if exception.kind_of?(::Interrupt)
          raise exception
        else
          elog('Error encountered with first Thread', error: exception)
        end
      end

      @tl.delete_if { |t| not t.alive? }
      tlb = @tl.length

      @range_done += (tla - tlb)
      check_show_progress if @show_progress
    end
  end

  #
  # Checks to see if a target is vulnerable.
  #
  def cmd_check(*args, opts: {})
    if (args.include?('-r') || args.include?('--reload-libs')) && !opts[:previously_reloaded]
      driver.run_single('reload_lib -a')
    end

    return false unless (args = parse_check_opts(args))

    mod_with_opts = mod.replicant
    mod_with_opts.datastore.import_options_from_hash(args[:datastore_options])

    begin
      mod_with_opts.validate
    rescue ::Msf::OptionValidateError => e
      ::Msf::Ui::Formatter::OptionValidateError.print_error(mod_with_opts, e)
      return false
    end

    begin
      check_multiple(mod_with_opts)
    rescue ::Interrupt
      # When the user sends interrupt trying to quit the task, some threads will still be active.
      # This means even though the console tells the user the task has aborted (or at least they
      # assume so), the checks are still running. Because of this, as soon as we detect interrupt,
      # we force the threads to die.
      if @tl
        @tl.each { |t| t.kill }
      end
      print_status("Caught interrupt from the console...")
      return
    end
  end

  def cmd_check_help
    print_module_run_or_check_usage(command: :check)
    print_line('Multi-threaded checks:')
    print_line('1. set THREADS 10')
    print_line('2. check')
    print_line
  end

  def report_vuln(instance)
    framework.db.report_vuln(
      workspace: instance.workspace,
      host: instance.rhost,
      name: instance.name,
      info: "This was flagged as vulnerable by the explicit check of #{instance.fullname}.",
      refs: instance.references
    )
  end

  def check_simple(instance=nil)
    unless instance
      instance = mod
    end

    rhost = instance.datastore['RHOST']
    rport = instance.datastore['RPORT']
    peer = rhost
    if rport
      rport = instance.rport if instance.respond_to?(:rport)
      peer = "#{rhost}:#{rport}"
    end
    peer_msg = peer ? "#{peer} - " : ''

    begin
      if instance.respond_to?(:check_simple)
        code = instance.check_simple(
          'LocalInput'  => driver.input,
          'LocalOutput' => driver.output
        )
      else
        msg = "Check failed: #{instance.type.capitalize} modules do not support check."
        raise NotImplementedError, msg
      end

      if (code && code.kind_of?(Msf::Exploit::CheckCode))
        if (code == Msf::Exploit::CheckCode::Vulnerable)
          print_good("#{peer_msg}#{code[1]}")
          # Restore RHOST for report_vuln
          instance.datastore['RHOST'] ||= rhost
          report_vuln(instance)
        else
          print_status("#{peer_msg}#{code[1]}")
        end
      else
        msg = "#{peer_msg}Check failed: The state could not be determined."
        print_error(msg)
        elog("#{msg}\n#{caller.join("\n")}")
      end
    rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error => e
      # Connection issues while running check should be handled by the module
      print_error("Check failed: #{e.class} #{e}")
      elog('Check Failed', error: e)
    rescue ::Msf::Exploit::Failed => e
      # Handle fail_with and other designated exploit failures
      print_error("Check failed: #{e.class} #{e}")
      elog('Check Failed', error: e)
    rescue ::RuntimeError => e
      # Some modules raise RuntimeError but we don't necessarily care about those when we run check()
      elog('Check Failed', error: e)
    rescue ::NotImplementedError => e
      print_error(e.message)
      elog('Check Failed', error: e)
    rescue ::Exception => e
      print_error("Check failed: #{e.class} #{e}")
      elog('Check Failed', error: e)
    end
  end

  #
  # Reloads the active module
  #
  def cmd_reload(*args)
    if args.include?('-r') || args.include?('--reload-libs')
      driver.run_single('reload_lib -a')
    end

    return cmd_reload_help if args.include?('-h') || args.include?('--help')

    begin
      reload
    rescue
      log_error("Failed to reload: #{$!}")
    end
  end

  @@reload_opts =  Rex::Parser::Arguments.new(
    '-k' => [ false,  'Stop the current job before reloading.' ],
    '-h' => [ false,  'Help banner.' ])

  def cmd_reload_help
    print_line "Usage: reload [-k]"
    print_line
    print_line "Reloads the current module."
    print @@reload_opts.usage
  end

  #
  # Reload the current module, optionally stopping existing job
  #
  def reload(should_stop_job=false)
    if should_stop_job and mod.job_id
      print_status('Stopping existing job...')

      framework.jobs.stop_job(mod.job_id)
      mod.job_id = nil
    end

    print_status('Reloading module...')

    original_mod = self.mod
    reloaded_mod = framework.modules.reload_module(original_mod)

    unless reloaded_mod
      error = framework.modules.module_load_error_by_path[original_mod.file_path]

      print_error("Failed to reload module: #{error}")

      self.mod = original_mod
    else
      self.mod = reloaded_mod

      self.mod.init_ui(driver.input, driver.output)
    end

    reloaded_mod
  end

end


end end end

