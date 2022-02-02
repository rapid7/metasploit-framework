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

    mod_with_opts = mod.replicant
    mod_with_opts.datastore.import_options_from_hash(args[:datastore_options])
    rhosts = mod_with_opts.datastore['RHOSTS']
    rhosts_walker = Msf::RhostsWalker.new(rhosts, mod_with_opts.datastore)

    begin
      mod_with_opts.validate
    rescue ::Msf::OptionValidateError => e
      ::Msf::Ui::Formatter::OptionValidateError.print_error(mod_with_opts, e)
      return false
    end

    begin
      # Check if this is a scanner module or doesn't target remote hosts
      if rhosts.blank? || mod.class.included_modules.include?(Msf::Auxiliary::Scanner)
        mod_with_opts.run_simple(
          'Action'         => args[:action],
          'LocalInput'     => driver.input,
          'LocalOutput'    => driver.output,
          'RunAsJob'       => jobify,
          'Quiet'          => args[:quiet]
        )
      # For multi target attempts with non-scanner modules.
      else
        rhosts_walker.each do |datastore|
          mod_with_opts = mod.replicant
          mod_with_opts.datastore.merge!(datastore)
          print_status("Running module against #{datastore['RHOSTS']}")
          mod_with_opts.run_simple(
            'Action'         => args[:action],
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
    rescue ::Msf::OptionValidateError => e
      ::Msf::Ui::Formatter::OptionValidateError.print_error(running_mod, e)
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

    if (jobify && mod_with_opts.job_id)
      print_status("Auxiliary module running as background job #{mod_with_opts.job_id}.")
    else
      print_status("Auxiliary module execution completed")
    end
  end

  alias cmd_exploit cmd_run
  alias cmd_exploit_tabs cmd_run_tabs

  def cmd_run_help
    print_module_run_or_check_usage(command: :run, options: @@module_opts)
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

