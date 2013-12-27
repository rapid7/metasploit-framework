# -*- coding: binary -*-

# Recon module command dispatcher.
class Msf::Ui::Console::CommandDispatcher::Post
  include Msf::Ui::Console::ModuleCommandDispatcher

  #
  # Class Varaibles
  #

  @@post_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner."                                          ],
    "-j" => [ false, "Run in the context of a job."                          ],
    "-o" => [ true,  "A comma separated list of options in VAR=VAL format."  ],
    "-q" => [ false, "Run the module in quiet mode with no output"           ]
  )

  #
  # Methods
  #

  #
  # Returns the hash of commands specific to post modules.
  #
  def commands
    super.merge(
      "run"   => "Launches the post exploitation module",
      "rerun" => "Reloads and launches the module",
      "exploit"  => "This is an alias for the run command",
      "rexploit" => "This is an alias for the rerun command"
    )
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
  # Reloads an auxiliary module and executes it
  #
  def cmd_rerun(*args)
    # Stop existing job and reload the module
    if reload(true)
      cmd_run(*args)
    end
  end

  alias cmd_rexploit cmd_rerun

  #
  # Executes an auxiliary module
  #
  def cmd_run(*args)
    fanged!

    opt_str = nil
    jobify  = false
    quiet   = false

    @@post_opts.parse(args) { |opt, idx, val|
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
          print(
            "Usage: run [options]\n\n" +
            "Launches a post module.\n" +
            @@post_opts.usage)
          return false
      end
    }

    # Always run passive modules in the background
    if (self.driver.metasploit_instance.passive)
      jobify = true
    end

    begin
      self.driver.metasploit_instance.run_simple(
        'OptionStr'      => opt_str,
        'LocalInput'     => driver.input,
        'LocalOutput'    => driver.output,
        'RunAsJob'       => jobify,
        'Quiet'          => quiet
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

    if (jobify)
      print_status("Post module running as background job")
    else
      print_status("Post module execution completed")
    end
  end

  alias cmd_exploit cmd_run

  def cmd_run_help
    print_line "Usage: run [options]"
    print_line
    print_line "Launches a post module."
    print @@auxiliary_opts.usage
  end

  alias cmd_exploit_help cmd_run_help

end
