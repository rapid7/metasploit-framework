##
# This module requires Metasploit: http://metasploit.com/download
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
        OptString.new('HttpUsername', [false, 'The username to login as']),
        OptString.new('HttpPassword', [false, 'The password to login with'])
      ])
  end

  def run
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']

    begin
      res = send_request_cgi(
        'uri'           => normalize_uri(target_uri.path),
        'method'        => 'GET',
        'authorization' => basic_auth(username, password)
      )

      temp = JSON.parse(res.body)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("The following Error was encountered: #{e.class}")
      return
    end

    if res.code == 200 && res.headers['Server'].include?('CouchDB')
      print_status('Enumerating...')
      results = JSON.pretty_generate(temp)
      print_good("Found:\n\n#{results}\n")

      path = store_loot(
        'couchdb.enum',
        'text/plain',
        rhost,
        results,
        'CouchDB Enum'
      )

      print_good("File saved in: #{path}")
    else
      print_error("Unable to enum, received \"#{res.code}\"")
    end
  end
end
