##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
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
      'License' => MSF_LICENSE
    ))

    register_options([
      Opt::RPORT(22)
    ])
  end

  def run_host(ip)
    connect
    banner = sock.get_once || ''
    sock.put(banner + "\n" * 8)
    response = sock.get_once || ''

    if response =~ /(?:^Protocol mismatch\.\n$|bad packet length)/
      print_good("#{ip}:#{rport} - Kippo detected!")
      report_service(
        :host => ip,
        :port => rport,
        :name => 'ssh',
        :info => 'Kippo SSH honeypot'
      )
    else
      vprint_status("#{ip}:#{rport} - #{banner.strip} detected")
    end
  end
end
