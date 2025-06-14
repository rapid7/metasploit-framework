##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::VIMSoap
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'VMware ESX/ESXi Fingerprint Scanner',
      'Description' => %(
        This module accesses the web API interfaces for VMware ESX/ESXi servers
        and attempts to identify version information for that server.
      ),
      'Author' => ['theLightCosine'],
      'License' => MSF_LICENSE,
      'DefaultOptions' => { 'SSL' => true },
      'Notes' => {
        'Stability' => [CRASH_SAFE],
        'SideEffects' => [],
        'Reliability' => []
      }
    )

    register_options([
      Opt::RPORT(443),
      OptString.new('URI', [false, 'The uri path to test against', '/sdk'])
    ])
  end

  def run_host(ip)
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
      'data' => soap_data,
      'headers' => { 'SOAPAction' => @soap_action }
    }, 25)

    fingerprint_vmware(ip, res)
  rescue ::Rex::ConnectionError => e
    vprint_error("http://#{ip}:#{rport}#{datastore['URI']} - #{e}")
    return false
  rescue StandardError
    vprint_error("Skipping #{ip} due to error - #{e}")
    return false
  end

  # Takes an IP address and a response, and just checks the response
  # to pull out version info. If it's ESX, report the OS as ESX (since
  # it's a hypervisor deal then). Otherwise, just report the service.
  # XXX: report_service is stomping on the report_host OS. This is le suck.
  def fingerprint_vmware(ip, res)
    unless res
      vprint_error("http://#{ip}:#{rport} - No response")
      return false
    end

    unless res.body.include?('<vendor>VMware, Inc.</vendor>')
      vprint_error("http://#{ip}:#{rport} - Host is not VMware")
      return false
    end

    os_match = res.body.match(%r{<name>([\w\s]+)</name>})
    ver_match = res.body.match(%r{<version>([\w\s.]+)</version>})
    build_match = res.body.match(%r{<build>([\w\s.-]+)</build>})
    full_match = res.body.match(%r{<fullName>([\w\s.-]+)</fullName>})
    this_host = nil

    if full_match
      print_good("#{rhost}:#{rport} - Identified #{full_match[1]}")
      report_service(host: this_host || ip, port: rport, proto: 'tcp', name: 'https', info: full_match[1])
    end

    unless os_match && ver_match && build_match
      vprint_error("http://#{ip}:#{rport} - Could not identify as VMware")
      return false
    end

    if os_match[1] =~ /ESX/ || os_match[1] =~ /vCenter/
      # Report a fingerprint match for OS identification
      report_note(
        host: ip,
        ntype: 'fingerprint.match',
        data: {
          'os.vendor' => 'VMware',
          'os.product' => os_match[1] + ' ' + ver_match[1],
          'os.version' => build_match[1]
        }
      )
    end

    return true
  end
end
