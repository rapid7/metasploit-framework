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


  @@auxiliary_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                                        ],
    "-j" => [ false, "Run in the context of a job."                                       ],
    "-o" => [ true,  "A comma separated list of options in VAR=VAL format."                ],
    "-a" => [ true,  "The action to use.  If none is specified, ACTION is used."           ],
    "-q" => [ false, "Run the module in quiet mode with no output"                         ]
  )

  #
  # Returns the hash of commands specific to auxiliary modules.
  #
  def commands
    super.update({
      "run"   => "Launches the auxiliary module",
      "rerun" => "Reloads and launches the auxiliary module",
      "exploit" => "This is an alias for the run command",
      "rexploit" => "This is an alias for the rerun command",
      "reload"   => "Reloads the auxiliary module"
    }).merge( (mod ? mod.auxiliary_commands : {}) )
  end

  #
  # Allow modules to define their own commands
  #
  def method_missing(meth, *args)
    if (mod and mod.respond_to?(meth.to_s))

      # Initialize user interaction
      mod.init_ui(driver.input, driver.output)

      return mod.send(meth.to_s, *args)
    end
    return
  end

  #
  #
  # Returns the command dispatcher name.
  #
  def name
    "Auxiliary"
  end

  #
  # Reloads an auxiliary module and executes it
  #
  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  #
  # Executes an auxiliary module
  #
  def cmd_run(*args)
    defanged?

    opt_str = nil
    action  = mod.datastore['ACTION']
    jobify  = false
    quiet   = false

    @@auxiliary_opts.parse(args) { |opt, idx, val|
      case opt
        when '-j'
          jobify = true
        when '-o'
          opt_str = val
        when '-a'
          action = val
        when '-q'
          quiet  = true
        when '-h'
          cmd_run_help
          return false
      end
    }

    # Always run passive modules in the background
    if (mod.passive or mod.passive_action?(action))
      jobify = true
    end

    begin
      mod.run_simple(
        'Action'         => action,
        'OptionStr'      => opt_str,
        'LocalInput'     => driver.input,
        'LocalOutput'    => driver.output,
        'RunAsJob'       => jobify,
        'Quiet'          => quiet
      )
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

    if (jobify)
      print_status("Auxiliary module running as background job")
    else
      print_status("Auxiliary module execution completed")
    end
  end

  alias cmd_exploit cmd_run

  def cmd_run_help
    print_line "Usage: run [options]"
    print_line
    print_line "Launches an auxiliary module."
    print @@auxiliary_opts.usage
  end

  alias cmd_exploit_help cmd_run_help

end

end end end end

