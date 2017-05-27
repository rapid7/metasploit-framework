##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::Udp
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Netcore Router Udp 53413 Backdoor Detection',
      'Description' => %q{
        Routers manufactured by Netcore, a popular brand for networking
        equipment in China, have a wide-open backdoor that can be fairly
        easily exploited by attackers. These products are also sold under
        the Netis brand name outside of China. This backdoor allows
        cybercriminals to easily run arbitrary code on these routers,
        rendering it vulnerable as a security device.
      },
      'Author'        =>
        [
          'Tim Yeh, Trend Micro',              # Discovery
          'h00die <mike[at]stcyrsecurity.com>',# Scanner
          'Nixawk'                             # Exploit Module
        ],
        'License'     => MSF_LICENSE,
        'References'  =>
        [
          [ 'URL', 'http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/' ]
        ],
        'DisclosureDate' => "Aug 25 2014" ))

    register_options([
        OptInt.new('TIMEOUT', [true, 'The socket response timeout in milliseconds', 1000]),
        Opt::RPORT(53413)
      ])
  end

  def do_report(ip)
    report_vuln({
      :host => ip,
      :port => rport,
      :name => "Netis Network Device Backdoor",
      :refs => self.references,
      :info => "Netis Network Device Backdoor found on device"
    })
  end

  def run_host(ip)
    begin
      connect_udp
      udp_sock.put("\x00" * 8)
      res = udp_sock.get(datastore['TIMEOUT'])
      if res.end_with?("\xD0\xA5Login:")
        #we need to try to login, but need the password first.
        #do_report(ip)
        print_good("#{ip}:#{rport} - Netis/Netcore backdoor detected.")
        do_report(ip)
      elsif res.end_with?("\x00\x00\x00\x05\x00\x01\x00\x00\x00\x00\x01\x00\x00")
        print_good("#{ip}:#{rport} - Netis/Netcore authenticated backdoor detected.")
        do_report(ip)
      else
        vprint_status("#{ip}:#{rport} - Backdoor not detected.")
      end
    rescue Rex::ConnectionError => e
      vprint_status("#{ip}:#{rport} - Connection failed: #{e.class}: #{e}")
    end
  end

end
