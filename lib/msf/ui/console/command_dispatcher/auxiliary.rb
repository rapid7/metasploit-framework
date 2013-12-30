# -*- coding: binary -*-

# Auxiliary module command dispatcher.
class Msf::Ui::Console::CommandDispatcher::Auxiliary
  include Metasploit::Framework::Command::Dispatcher
  include Msf::Ui::Console::ModuleCommandDispatcher

  #
  # Class Variables
  #

  @@auxiliary_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                                        ],
    "-j" => [ false, "Run in the context of a job."                                       ],
    "-o" => [ true,  "A comma separated list of options in VAR=VAL format."                ],
    "-a" => [ true,  "The action to use.  If none is specified, ACTION is used."           ],
    "-q" => [ false, "Run the module in quiet mode with no output"                         ]
  )

  #
  # Methods
  #

  # Reloads an auxiliary module and executes it
  #
  # @return [void]
  def cmd_rerun(*args)
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  # Executes an auxiliary module
  #
  # @param args [Array<String>] Arguments for `run`.
  # @return [void]
  def cmd_run(*args)
    fanged!

    opt_str = nil
    action  = self.driver.metasploit_instance.datastore['ACTION']
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
    if (self.driver.metasploit_instance.passive or self.driver.metasploit_instance.passive_action?(action))
      jobify = true
    end

    begin
      self.driver.metasploit_instance.run_simple(
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

  # Returns the hash of commands specific to auxiliary modules.
  #
  # @return [Hash{String => String}] Map String names to String descriptions.
  def commands
    super.merge(
      "run"   => "Launches the auxiliary module",
      "rerun" => "Reloads and launches the auxiliary module",
      "exploit" => "This is an alias for the run command",
      "rexploit" => "This is an alias for the rerun command"
    ).merge(
        metasploit_instance.auxiliary_commands
    )
  end

  # Allow modules to define their own commands
  #
  # @param method_name [Symbol] Name of missing method.
  # @param args [Array<Object>] Arguments to the method.
  # @param block [Proc] block to pass to method.
  # @return [Object] return from `method_name` method.
  def method_missing(method_name, *args, &block)
    if driver.metasploit_instance.respond_to? method_name
      driver.metasploit_instance.init_ui(driver.input, driver.output)

      driver.metasploit_instance.send(method_name, *args, &block)
    else
      super
    end
  end

  # Returns the command dispatcher name.
  #
  # @return [String] 'Auxiliary'
  def name
    "Auxiliary"
  end

  def respond_to_missing?(method_name, include_private=false)
    driver.metasploit_instance.respond_to?(method_name, include_private) || super
  end
end

