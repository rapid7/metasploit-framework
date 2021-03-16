# -*- coding: binary -*-
module Msf
module Ui
module Console
module CommandDispatcher

###
#
# Recon module command dispatcher.
#
###
class Auxiliary

  include Msf::Ui::Console::ModuleCommandDispatcher
  include Msf::Ui::Console::ModuleActionCommands
  include Msf::Ui::Console::ModuleOptionTabCompletion

  #
  # Returns the hash of commands specific to auxiliary modules.
  #
  def commands
    super.merge({
      "run"      => "Launches the auxiliary module",
      "rcheck"   => "Reloads the module and checks if the target is vulnerable",
      "rerun"    => "Reloads and launches the auxiliary module",
      "exploit"  => "This is an alias for the run command",
      "recheck"  => "This is an alias for the rcheck command",
      "rexploit" => "This is an alias for the rerun command",
      "reload"   => "Reloads the auxiliary module"
    }).merge( (mod ? mod.auxiliary_commands : {}) )
  end

  #
  #
  # Returns the command dispatcher name.
  #
  def name
    "Auxiliary"
  end

  #
  # Executes an auxiliary module
  #
  def cmd_run(*args, action: nil)
    return false unless (args = parse_run_opts(args, action: action))
    jobify = args[:jobify]

    # Always run passive modules in the background
    if mod.is_a?(Msf::Module::HasActions) &&
        (mod.passive || mod.passive_action?(args[:action] || mod.default_action))
      jobify = true
    end

    rhosts = datastore['RHOSTS']
    begin
      # Check if this is a scanner module or doesn't target remote hosts
      if rhosts.blank? || mod.class.included_modules.include?(Msf::Auxiliary::Scanner)
        mod.run_simple(
          'Action'         => args[:action],
          'OptionStr'      => args[:datastore_options].map { |k,v| "#{k}=#{v}" }.join(','),
          'LocalInput'     => driver.input,
          'LocalOutput'    => driver.output,
          'RunAsJob'       => jobify,
          'Quiet'          => args[:quiet]
        )
      # For multi target attempts with non-scanner modules.
      else
        rhosts_opt = Msf::OptAddressRange.new('RHOSTS')
        if !rhosts_opt.valid?(rhosts)
          print_error("Auxiliary failed: option RHOSTS failed to validate.")
          return false
        end

        rhosts_range = Rex::Socket::RangeWalker.new(rhosts_opt.normalize(rhosts))
        rhosts_range.each do |rhost|
          nmod = mod.replicant
          nmod.datastore['RHOST'] = rhost
          nmod.datastore['VHOST'] = rhosts if (!Rex::Socket.is_ip_addr?(rhosts) && nmod.is_a?(Msf::Exploit::Remote::HttpClient) && nmod.datastore['VHOST'].nil?)
          print_status("Running module against #{rhost}")
          nmod.run_simple(
            'Action'         => args[:action],
            'OptionStr'      => args[:datastore_options].map { |k,v| "#{k}=#{v}" }.join(','),
            'LocalInput'     => driver.input,
            'LocalOutput'    => driver.output,
            'RunAsJob'       => false,
            'Quiet'          => args[:quiet]
          )
        end
      end
    rescue ::Timeout::Error
      print_error("Auxiliary triggered a timeout exception")
      print_error("Call stack:")
      e.backtrace.each do |line|
        break if line =~ /lib.msf.base.simple/
        print_error("  #{line}")
      end
    rescue ::Interrupt
      print_error("Auxiliary interrupted by the console user")
    rescue ::Exception => e
      print_error("Auxiliary failed: #{e.class} #{e}")
      if(e.class.to_s != 'Msf::OptionValidateError')
        print_error("Call stack:")
        e.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple/
          print_error("  #{line}")
        end
      end

      return false
    end

    if (jobify && mod.job_id)
      print_status("Auxiliary module running as background job #{mod.job_id}.")
    else
      print_status("Auxiliary module execution completed")
    end
  end

  alias cmd_exploit cmd_run
  alias cmd_exploit_tabs cmd_run_tabs

  def cmd_run_help
    print_line "Usage: run [options]"
    print_line
    print_line "Launches an auxiliary module."
    print @@module_opts.usage
  end

  alias cmd_exploit_help cmd_run_help

  #
  # Reloads an auxiliary module and executes it
  #
  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rerun_tabs cmd_run_tabs
  alias cmd_rexploit cmd_rerun
  alias cmd_rexploit_tabs cmd_exploit_tabs

  #
  # Reloads an auxiliary module and checks the target to see if it's
  # vulnerable.
  #
  def cmd_rcheck(*args)
    reload()

    cmd_check(*args)
  end

  alias cmd_recheck cmd_rcheck

end

end end end end

