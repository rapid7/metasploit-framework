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
      'Name'        => 'Netis/Netcore Network Device Backdoor Detection',
      'Description' => %q{
        This module can identify Netcore (Chinese) and Netis manufactured
        network devices which contain a backdoor, allowing command
        injection or account disclosure.
      },
      'Author'        =>
        [
          'Tim Yeh, Trend Micro',              # Discovery
          'h00die <mike[at]stcyrsecurity.com>' # Module
        ],
        'License'     => MSF_LICENSE,
        'References'  =>
        [
          [ 'URL', 'http://blog.trendmicro.com/trendlabs-security-intelligence/netis-routers-leave-wide-open-backdoor/' ]
        ],
        'DisclosureDate' => "Aug 25 2014" ))

    register_options([
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
      connect
      sock.put(Rex::Text.rand_text(5))
      res = sock.get_once
      if res.start_with?("login")
        #we need to try to login, but need the password first.
        #do_report(ip)
        vprint_status("#{ip}:#{rport} - Backdoor not detected.")
      end
    rescue Rex::ConnectionError => e
      vprint_status("#{ip}:#{rport} - Connection failed: #{e.class}: #{e}")
    end
  end

end
