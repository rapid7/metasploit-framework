##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'CouchDB Enum Utility',
      'Description'    => %q{
        This module enumerates databases on CouchDB using the REST API
        (without authentication by default).
      },
      'References'     =>
        [
          ['URL', 'https://wiki.apache.org/couchdb/HTTP_database_API']
        ],
      'Author'         => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>' ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/_all_dbs']),
        OptBool.new('SERVERINFO', [true, 'Print server info']),
        OptString.new('HttpUsername', [false, 'The username to login as']),
        OptString.new('HttpPassword', [false, 'The password to login with'])
      ])
  end

  def valid_response(res)
    return res.code == 200 && res.headers['Server'].include?('CouchDB')
  end

  def get_dbs(auth)
    begin
      res = send_request_cgi(
        'uri'           => normalize_uri(target_uri.path),
        'method'        => 'GET',
        'authorization' => auth
      )

      temp = JSON.parse(res.body)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("#{peer} The following Error was encountered: #{e.class}")
      return
    end

    if valid_response(res)
      print_status("#{peer} Enumerating Databases...")
      results = JSON.pretty_generate(temp)
      print_good("#{peer} Databases:\n\n#{results}\n")

      path = store_loot(
        'couchdb.enum',
        'application/json',
        rhost,
        results,
        'CouchDB Databases'
      )

      print_good("#{peer} File saved in: #{path}")
    else
      print_error("#{peer} Unable to enum, received \"#{res.code}\"")
    end
  end

  def get_server_info(auth)
    begin
      res = send_request_cgi(
        'uri'           => '/',
        'method'        => 'GET',
        'authorization' => auth
      )

      temp = JSON.parse(res.body)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("#{peer} The following Error was encountered: #{e.class}")
      return
    end

    if valid_response(res)
      # Example response: {"couchdb":"Welcome","uuid":"6f08e89795bd845efc6c2bf3d57799e5","version":"1.6.1","vendor":{"version":"16.04","name":"Ubuntu"}}

      print_good("#{peer} #{JSON.pretty_generate(temp)}")
      report_service(
        host: rhost,
        port: rport,
        name: 'couchdb',
        proto: 'tcp',
        info: res.body
      )
    else
      print_error("#{peer} Unable to enum, received \"#{res.code}\"")
    end
  end

  def run
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']
    auth = basic_auth(username, password) if username && password
    if datastore['SERVERINFO']
      get_server_info(auth)
    end
    get_dbs(auth)
  end
end
