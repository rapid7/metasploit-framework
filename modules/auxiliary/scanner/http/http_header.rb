##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'        => 'HTTP Header Detection',
      'Description' => %q{ This module shows HTTP Headers returned by the scanned systems. },
      'Author'      =>
      [
        'Christian Mehlmauer',
        'rick2600'
      ],
      'References'  =>
      [
        ['URL', 'http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html'],
        ['URL', 'http://en.wikipedia.org/wiki/List_of_HTTP_header_fields']
      ],
      'License'     => MSF_LICENSE
    ))

    register_options([
      OptString.new('IGN_HEADER', [ true, 'List of headers to ignore, separated by comma',
        'Vary,Date,Content-Length,Connection,Etag,Expires,Pragma,Accept-Ranges']),
      OptEnum.new('HTTP_METHOD', [ true, 'HTTP Method to use, HEAD or GET', 'HEAD', ['GET', 'HEAD'] ]),
      OptString.new('TARGETURI', [ true, 'The URI to use', '/'])
    ])
  end

  def run_host(ip)
    ignored_headers = datastore['IGN_HEADER'].split(',')

    uri = normalize_uri(target_uri.path)
    method = datastore['HTTP_METHOD']
    vprint_status("#{peer}: requesting #{uri} via #{method}")
    res = send_request_raw({
      'method'  => method,
      'uri'     => uri
    })

    unless res
      vprint_error("#{peer}: connection timed out")
      return
    end

    headers = res.headers
    unless headers
      vprint_status("#{peer}: no headers returned")
      return
    end

    # Header Names are case insensitve so convert them to upcase
    headers_uppercase = headers.inject({}) do |hash, keys|
      hash[keys[0].upcase] = keys[1]
      hash
    end

    ignored_headers.each do |h|
      if headers_uppercase.has_key?(h.upcase)
        vprint_status("#{peer}: deleted header #{h}")
        headers_uppercase.delete(h.upcase)
      end
    end
    headers_uppercase.to_a.compact.sort

    counter = 0;
    headers_uppercase.each do |h|
      header_string = "#{h[0]}: #{h[1]}"
      print_good "#{peer}: #{header_string}"

      report_note(
        :type => "http.header.#{rport}.#{counter}",
        :data => header_string,
        :host => ip,
        :port => rport
      )
      counter = counter + 1
    end
    if counter == 0
      print_warning "#{peer}: all detected headers are defined in IGN_HEADER and were ignored "
    else
      print_good "#{peer}: detected #{counter} headers"
    end
  end
end
