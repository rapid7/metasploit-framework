##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Kippo SSH Honeypot Detector',
        'Description' => %q{
          This module will detect if an SSH server is running a Kippo honeypot.
          This is done by issuing unexpected data to the SSH service and checking
          the response returned for two particular non-standard error messages.
        },
        'Author' => 'Andrew Morris <andrew[at]morris.guru>',
        'References' => [
          ['URL', 'https://www.obscurechannel.com/x42/magicknumber.html'],
          ['URL', 'http://morris.guru/detecting-kippo-ssh-honeypots/']
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Reliability' => UNKNOWN_RELIABILITY,
          'Stability' => UNKNOWN_STABILITY,
          'SideEffects' => UNKNOWN_SIDE_EFFECTS
        }
      )
    )

    register_options([
      Opt::RPORT(22)
    ])
  end

  def report_ssh_service(info: nil)
    report_service(
      host: rhost,
      port: rport,
      name: 'ssh',
      proto: 'tcp',
      info: info.to_s.strip
    )
  end

  def report_ssh_vuln(info: nil)
    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      sname: 'ssh',
      name: 'SSH Honeypot Detected',
      info: info.to_s.strip,
      refs: references
    )
  end

  def check_kippo(banner, response)
    unless response =~ /(?:^Protocol mismatch\.\n$|bad packet length)/
      vprint_status('Not thought to be Kippo - Received expected SSH probe')
      return false
    end

    print_good("SSH honeypot detected: Kippo (highly likely)")
    report_ssh_service(info: "SSH honeypot: Kippo (#{banner.strip})")
    report_ssh_vuln(info: 'SSH honeypot: Kippo - Server gave incorrect response when probed')
    true
  end

  def run_host(ip)
    connect
    banner = sock.get_once || ''
    sock.put(banner + "\n" * 8)
    response = sock.get_once || ''

    vprint_status("SSH banner: #{banner.strip}")

    return if check_kippo(banner, response)

    print_status('No SSH honeypot detected')
    report_ssh_service(info: banner)
  rescue Rex::ConnectionError
    print_error('Connection refused or timed out')
  ensure
    disconnect
  end
end
