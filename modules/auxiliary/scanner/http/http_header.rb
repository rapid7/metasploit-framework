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
      'Name'        => 'HTTP Header Detection',
      'Description' => %q{ This module shows HTTP Headers returned by the scanned systems. },
      'Author'      => ['Christian Mehlmauer <FireFart[at]gmail.com>'],
      'References'  =>
      [
        ['URL','http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html'],
        ['URL','http://en.wikipedia.org/wiki/List_of_HTTP_header_fields']
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptString.new('IGN_HEADER', [ true, 'List of headers to ignore, seperated by comma',
        'Vary,Date,Content-Length,Connection,Etag,Expires,Pragma,Accept-Ranges']),
      OptString.new('HTTP_METHOD', [ true, 'HTTP Method to use, HEAD or GET', 'HEAD', ['GET', 'HEAD'] ])
    ])
  end

  def run_host(ip)

    ignored_headers = datastore['IGN_HEADER'].split(',')

    vprint_status("Requesting #{peer}")
    res = send_request_raw({'method' => datastore['HTTP_METHOD']})

    if res
      headers = res.headers

      if headers
        # Header Names are case insensitve so convert them to upcase
        headers_uppercase = headers.inject({}) do |hash, keys|
          hash[keys[0].upcase] = keys[1]
          hash
        end

        ignored_headers.each do |h|
          if headers_uppercase.has_key?(h.upcase)
            vprint_status("#{peer}: Deleted Header #{h}")
            headers_uppercase.delete(h.upcase)
          end
        end
        headers_uppercase.to_a.compact.sort

        headers_uppercase.each do |h|
          header_string = "#{h[0]}: #{h[1]}"
          vprint_status("#{peer}: #{header_string}")

          report_note({
            :type => 'HTTP Header',
            :data => header_string,
            :host => ip,
            :port => rport
          })
        end
      else
        vprint_status("#{peer}: No headers returned")
      end
    else
      vprint_error("#{peer}: No Connection")
    end
  end

end
