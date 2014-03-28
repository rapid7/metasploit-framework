##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'
require 'msf/core'


class Metasploit3 < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP Title Parser',
      'Description' => %q{Reports back web page titles. Very useful for when
      you have numerous web servers to inspect and need to figure out what's
      running on them. Other methods exist, such as taking screenshots, but
      they may potentially be a slower process.},
      'Author'      => 'Alton Johnson alton.jx[at]gmail.com',
      'License'     => MSF_LICENSE
    )

      register_options([
            OptInt.new('ReadBytes', [false, "Specify # of bytes to parse. 0 to parse entire pages", 0]),
            OptBool.new('SSL', [false, "Negotiate SSL connection", false])
         ], self.class)

    register_wmap_options({
        'OrderID' => 0,
        'Require' => {},
      })
  end

  def run_host(ip)
    begin
      connect

         opts = {'uri' => '/',
         'method' => 'GET',
         'SSL' => datastore['SSL']
         }

      res = send_request_cgi(opts)
      return if not res

         if datastore['ReadBytes'] == 0
            body = res.body.to_s
         else
            body = res.body.to_s[0..datastore['ReadBytes']]
         end

         # Parse web page response.
         if (res.code >= 300 and res.code < 400) or body.include? "location.replace(\"https:"
            print_error("#{ip}:#{rport} - 3xx or Java redirect")
         elsif res.code >= 200 and res.code < 300
            print_title(ip, rport, body)
         elsif res.code >= 300 and res.code < 400
            print_error("#{ip}:#{rport} - <#{res.code} HTTP Response>")
         elsif res.code >= 400 and res.code < 500
            print_error("#{ip}:#{rport} - <#{res.code} HTTP Response>")
         elsif res.code >= 500 and res.code < 600
            print_error("#{ip}:#{rport} - <#{res.code} HTTP Response>")
         end

         disconnect
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end

   def print_title(ip, rport, response)
      title = response.to_s[/<title[^>]*>(.*?)<\/title>/im,1]
    begin
      title = title.strip
    rescue
    end
      if title.to_s.length == 0
          print_error("#{ip}:#{rport} - <No title found>")
      else
          print_good("#{ip}:#{rport} - #{title}")
      end
   end

end
