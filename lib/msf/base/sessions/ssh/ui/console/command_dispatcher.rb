
class Msf::Sessions::SSH::Ui::Console::CommandDispatcher

  include Rex::Ui::Text::DispatcherShell::CommandDispatcher

  # @return [Msf::Sessions::SSH::Ui::Console]
  attr_accessor :shell

  def initialize(shell)
    @shell = shell
  end

  # @return [Msf::Sessions::SSH]
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
    shell.client.ssh.forward.active_locals.each do |port, host|
      shell.client.ssh.forward.cancel_local(port, host)
    end
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

    self.shell.client.ssh.forward.local(lport, rhost, rport)
  end

  #
  # Options for the portfwd command.
  #
  @@portfwd_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner.'],
    '-R' => [false, 'Reverse forward, [remote bind address:]<remote port>:<host>:<port>'],
    '-L' => [true,  'Local forward, [local bind address:]<local port>:<host>:<port>'])


  def cmd_portfwd(*args)
    args.unshift('list') if args.empty?

    # For clarity's sake.
    lport = nil
    lhost = nil
    rport = nil
    rhost = nil
    reverse = false
    index = nil

    # Parse the options
    @@portfwd_opts.parse(args) do |opt, idx, val|
      case opt
      when '-h'
        cmd_portfwd_help
        return true
      when '-l'
        lport = val.to_i
      when '-L'
        parts = val.split(":")
        rport = parts.pop
        rhost = parts.pop
        lport = parts.pop
        lhost = parts.pop
      when '-p'
        rport = val.to_i
      when '-r'
        rhost = val
      when '-R'
        reverse = true
      when '-i'
        index = val.to_i
      end
    end

    # Process the command
    case args.shift
    when 'list'
      portfwd_list
    when 'add'
      $stderr.puts(args.join("\n"))
      portfwd_add(lhost, lport, rhost, rport)
    when 'delete', 'remove', 'del', 'rm'
    when 'flush'
    else
      cmd_portfwd_help
    end
    $stderr.puts("Done")
  end

  def cmd_portfwd_help
    print_line "Usage: portfwd [-h] [add | delete | list | flush] [args]"
    print_line
    print @@portfwd_opts.usage
  end

  def portfwd_add(lhost, lport, rhost, rport)
    lhost ||= "127.0.0.1"
    lport ||= 0

    shell.client.ssh.logger.level = 0
    listening_port = shell.client.forward_local(lhost, lport, rhost, rport)

    sleep 1
    p shell.client.ssh.forward.active_locals
    p listening_port
  end

  def portfwd_list
    p shell.client.ssh.forward.active_locals
    table = Rex::Text::Table.new(
      'Header'    => 'Active Port Forwards',
      'Indent'    => 3,
      'SortIndex' => -1,
      'Columns'   => ['Index', 'Local', 'Remote', 'Direction'])

    cnt = 0

    shell.client.ssh.forward.active_locals.each do |port, address|
      cnt += 1
      table << [ cnt, "#{address}:#{port}", "", "Forward" ]
    end

    shell.client.ssh.forward.active_remotes.each do |port, address|
      cnt += 1
      table << [ cnt, "", "#{address}:#{port}", "Reverse" ]
    end

    print_line
    if cnt > 0
      print_line(table.to_s)
      print_line("#{cnt} total active port forwards.")
    else
      print_line('No port forwards are currently active.')
    end
    print_line
  end

end
