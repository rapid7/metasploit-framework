##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::Tcp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'SerComm Network Device Backdoor Detection',
      'Description' => %q{
        This module can identify SerComm manufactured network devices which
        contain a backdoor, allowing command injection or account disclosure.
      },
      'Author'         =>
        [
          'Eloi Vanderbeken <eloi.vanderbeken[at]gmail.com>', # Initial discovery, poc
          'Matt "hostess" Andreko <mandreko[at]accuvant.com>' # Msf module
        ],
        'License'     => MSF_LICENSE,
        'References'     =>
        [
          [ 'CVE', '2014-0659' ],
          [ 'OSVDB', '101653' ],
          [ 'URL', 'https://github.com/elvanderb/TCP-32764' ]
        ],
        'DisclosureDate' => '2013-12-31' ))

    register_options([
        Opt::RPORT(32764)
      ])
  end

  def do_report(ip, endianness)
    report_vuln({
      :host => ip,
      :port => rport,
      :name => "SerComm Network Device Backdoor",
      :refs => self.references,
      :info => "SerComm Network Device Backdoor found on a #{endianness} device"
    })
  end

  def run_host(ip)
    begin
      connect
      sock.put(Rex::Text.rand_text(5))
      res = sock.get_once
      disconnect

      if (res && res.start_with?("MMcS"))
        print_good("#{ip}:#{rport} - Possible backdoor detected - Big Endian")
        do_report(ip, "Big Endian")
      elsif (res && res.start_with?("ScMM"))
        print_good("#{ip}:#{rport} - Possible backdoor detected - Little Endian")
        do_report(ip, "Little Endian")
      else
        vprint_status("#{ip}:#{rport} - Backdoor not detected.")
      end
    rescue Rex::ConnectionError => e
      vprint_error("#{ip}:#{rport} - Connection failed: #{e.class}: #{e}")
    end
  end
end
