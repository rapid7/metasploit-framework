##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'winrm'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::WinRM
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::CommandShell

  def initialize
    super(
      'Name'           => 'WinRM Command Runner',
      'Description'    => %q{
        This module runs arbitrary Windows commands using the WinRM Service
        },
      'Author'         => [ 'thelightcosine' ],
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('CMD', [ true, "The windows command to run", "ipconfig /all" ]),
        OptString.new('USERNAME', [ true, "The username to authenticate as"]),
        OptString.new('PASSWORD', [ true, "The password to authenticate with"])
      ])
  end

  class LogProxy
    def debug(msg)
    end
    def warn(msg)
      vprint_warning(msg)
    end

  end

  def run_host(ip)
    rhost = datastore['RHOST']
    rport = datastore['RPORT']
    endpoint = "http://#{rhost}:#{rport}}"
    overrides = {
      endpoint: endpoint,
      user: datastore['USERNAME'],
      password: datastore['PASSWORD']
    }
    opts = WinRM::ConnectionOpts.create_with_defaults(overrides)
    rex_transport = nil
    logger = LogProxy.new()
    cmd_shell = WinRM::Shells::Cmd.new(opts, rex_transport, logger)
    cmd_shell.run("whoami")

    shell_id = winrm_get_shell_id(resp)
    session_setup(shell_id) if datastore['CreateSession']
    # TODO

    #return unless streams.class == Hash
    #print_error streams['stderr'] unless streams['stderr'] == ''
    #print_good "#{peer}: #{streams['stdout']}"
    #path = store_loot("winrm.cmd_results", "text/plain", ip, streams['stdout'], "winrm_cmd_results.txt", "WinRM CMD Results")
    #print_good "Results saved to #{path}"
  end

  def session_setup(shell_id)
    sess = Msf::Sessions::WinrmCommandShell.new(shell_id,self)
    info = "AAAAAAAAAAAAAAAAAAAAA"
    merge_me = {
      'USERNAME' => datastore['USERNAME'],
      'PASSWORD' => datastore['PASS']
    }

    start_session(self, info, merge_me,false,sess.rstream,sess)
    # NEEDED???
    host_info = {os_name: 'Windows'}
    report_host(host_info)
  end


end

