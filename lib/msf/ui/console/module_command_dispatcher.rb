# -*- coding: binary -*-
require 'msf/ui/console/command_dispatcher'

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

  def commands
    {
      "pry"    => "Open a Pry session on the current module",
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

  def check_multiple(hosts)
    # This part of the code is mostly from scanner.rb
    @show_progress = framework.datastore['ShowProgress'] || mod.datastore['ShowProgress'] || false
    @show_percent  = ( framework.datastore['ShowProgressPercent'] || mod.datastore['ShowProgressPercent'] ).to_i

    @range_count   = hosts.length || 0
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
      while (@tl.length < threads_max)
        ip = hosts.next_ip
        break unless ip

        @tl << framework.threads.spawn("CheckHost-#{ip}", false, ip.dup) { |tip|
          # Make sure this is thread-safe when assigning an IP to the RHOST
          # datastore option
          instance = mod.replicant
          instance.datastore['RHOST'] = tip.dup
          Msf::Simple::Framework.simplify_module(instance, false)
          check_simple(instance)
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
          elog("#{exception} #{exception.class}:\n#{exception.backtrace.join("\n")}")
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
  def cmd_check(*args)
    ip_range_arg = args.shift || mod.datastore['RHOSTS'] || framework.datastore['RHOSTS'] || ''
    opt = Msf::OptAddressRange.new('RHOSTS')

    begin
      if !ip_range_arg.blank? && opt.valid?(ip_range_arg)
        hosts = Rex::Socket::RangeWalker.new(opt.normalize(ip_range_arg))

        # Check multiple hosts
        last_rhost_opt = mod.datastore['RHOST']
        last_rhosts_opt = mod.datastore['RHOSTS']
        mod.datastore['RHOSTS'] = ip_range_arg
        begin
          check_multiple(hosts)
        ensure
          # Restore the original rhost if set
          mod.datastore['RHOST'] = last_rhost_opt
          mod.datastore['RHOSTS'] = last_rhosts_opt
          mod.cleanup
        end
      else
        # Check a single rhost
        unless Msf::OptAddress.new('RHOST').valid?(mod.datastore['RHOST'])
          raise Msf::OptionValidateError.new(['RHOST'])
        end
        check_simple
      end

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
    rport = nil
    peer = rhost
    if instance.datastore['rport']
      rport = instance.rport
      peer = "#{rhost}:#{rport}"
    end

    begin
      code = instance.check_simple(
        'LocalInput'  => driver.input,
        'LocalOutput' => driver.output)
      if (code and code.kind_of?(Array) and code.length > 1)
        if (code == Msf::Exploit::CheckCode::Vulnerable)
          print_good("#{peer} #{code[1]}")
          report_vuln(instance)
        else
          print_status("#{peer} #{code[1]}")
        end
      else
        msg = "#{peer} Check failed: The state could not be determined."
        print_error(msg)
        elog("#{msg}\n#{caller.join("\n")}")
      end
    rescue ::Rex::ConnectionError, ::Rex::ConnectionProxyError, ::Errno::ECONNRESET, ::Errno::EINTR, ::Rex::TimeoutError, ::Timeout::Error => e
      # Connection issues while running check should be handled by the module
      elog("#{e.message}\n#{e.backtrace.join("\n")}")
    rescue ::RuntimeError => e
      # Some modules raise RuntimeError but we don't necessarily care about those when we run check()
      elog("#{e.message}\n#{e.backtrace.join("\n")}")
    rescue Msf::OptionValidateError => e
      print_error("{peer} - Check failed: #{e.message}")
      elog("#{e.message}\n#{e.backtrace.join("\n")}")
    rescue ::Exception => e
      print_error("Check failed: #{e.class} #{e}")
      elog("#{e.message}\n#{e.backtrace.join("\n")}")
    end
  end

  def cmd_pry_help
    print_line "Usage: pry"
    print_line
    print_line "Open a pry session on the current module.  Be careful, you"
    print_line "can break things."
    print_line
  end

  def cmd_pry(*args)
    begin
      require 'pry'
    rescue LoadError
      print_error("Failed to load pry, try 'gem install pry'")
      return
    end
    mod.pry
  end

  #
  # Reloads the active module
  #
  def cmd_reload(*args)
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

