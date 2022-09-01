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
class Post

  include Msf::Ui::Console::ModuleCommandDispatcher
  include Msf::Ui::Console::ModuleActionCommands
  include Msf::Ui::Console::ModuleOptionTabCompletion
  include Msf::Ui::Console::ModuleArgumentParsing

  #
  # Returns the hash of commands specific to post modules.
  #
  def commands
    super.merge({
      "run"   => "Launches the post exploitation module",
      "rerun" => "Reloads and launches the module",
      "exploit"  => "This is an alias for the run command",
      "rexploit" => "This is an alias for the rerun command",
    }).merge( (mod ? mod.post_commands : {}) )
  end

  #
  #
  # Returns the command dispatcher name.
  #
  def name
    "Post"
  end

  #
  # This is an alias for 'rerun'
  #
  def cmd_rexploit(*args)
    cmd_rerun(*args)
  end

  #
  # Reloads a post module and executes it
  #
  def cmd_rerun(*args)
    # Stop existing job and reload the module
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  def cmd_run_help
    print_module_run_or_check_usage(
      command: :run,
      description: 'Launches a post exploitation module.'
    )
  end

  #
  # Executes a post module
  #
  def cmd_run(*args, action: nil)
    return false unless (args = parse_run_opts(args, action: action))
    jobify = args[:jobify]

    # Always run passive modules in the background
    if (mod.passive)
      jobify = true
    end

    begin
      mod.run_simple(
        'Action'         => args[:action],
        'OptionStr'      => args[:datastore_options].map { |k,v| "#{k}=#{v}" }.join(','),
        'LocalInput'     => driver.input,
        'LocalOutput'    => driver.output,
        'RunAsJob'       => jobify,
        'Quiet'          => args[:quiet]
      )
    rescue ::Timeout::Error
      print_error("Post triggered a timeout exception")
    rescue ::Interrupt
      print_error("Post interrupted by the console user")
    rescue ::Exception => e
      print_error("Post failed: #{e.class} #{e}")
      if (e.class.to_s != 'Msf::OptionValidateError')
        print_error("Call stack:")
        e.backtrace.each do |line|
          break if line =~ /lib.msf.base.simple/
          print_error("  #{line}")
        end
      end

      return false
    end

    if (jobify && mod.job_id)
      print_status("Post module running as background job #{mod.job_id}.")
    else
      print_status("Post module execution completed")
    end
  end

  alias cmd_exploit cmd_run

  alias cmd_exploit_tabs cmd_run_tabs

  def cmd_run_help
    print_line "Usage: run [options]"
    print_line
    print_line "Launches a post module."
    print @@module_opts_with_action_support.usage
  end

  alias cmd_exploit_help cmd_run_help

end

end end end end

