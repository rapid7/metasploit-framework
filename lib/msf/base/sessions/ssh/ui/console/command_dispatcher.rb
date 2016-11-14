
class Msf::Sessions::SSH::Ui::Console::CommandDispatcher

  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  attr_accessor :shell

  def initialize(shell)
    $stderr.puts(shell.client.ssh.closed?)
    @shell = shell
  end

  def client
    shell.client
  end

  def name
    "metassh"
  end

  def commands
    {
      "background" => "background",
      "execute" => "execute",
      "exit" => "exit",
      "help" => "Help menu",
      "irb" => "irb",
      "portfwd" => "forward local port to remote port",
    }
  end

  def cmd_background_help
    print_line "Usage: background"
    print_line
    print_line "Stop interacting with this session and return to the parent prompt"
    print_line
  end

  def cmd_background
    shell.client.interacting = false
  end

  def cmd_execute(*args)
    args ||= []
    full_cmd = "#{args.join(' ')}\n"
    out = self.shell.client.ssh.exec!(full_cmd)
    print_line out
  end

  #
  # Terminates the metaSSH session.
  #
  def cmd_exit(*args)
    print_status("Shutting down metaSSH...")
    shell.stop
  end

  alias cmd_quit cmd_exit


  #
  # Runs the IRB scripting shell
  #
  def cmd_irb(*args)
    print_status("Starting IRB shell")
    print_status("The 'client' variable holds the metaSSH client\n")

    Rex::Ui::Text::IrbShell.new(binding).run
  end


  def cmd_portfwd(*args)
    if args.delete('-h')
      return cmd_portfwd_help
    end

    self.shell.client.ssh.forward.extend(Msf::Sessions::SSH::Extensions::Stdapi::Net::SocketSubsystem::ForwardMixin)
    self.shell.client.ssh.forward.local(lport, rhost, rport)
    true
  end

  def cmd_portfwd_help
    print_line "Usage: portfwd [-h] [add | delete | list | flush] [args]"
    print_line
    print @@portfwd_opts.usage
  end

end
