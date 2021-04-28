##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name' => 'Emby Version Checker',
      'Description' => 'This module attempts to identify the version of an Emby Media Server running on a host. If you wish to see all the information available, set VERBOSE to true. Use in conjunction with emby_ssrf_scanner to locate devices vulnerable to CVE-2020-26948.',
      'Author' => 'Btnz',
      'License' => MSF_LICENSE,
      'Disclosure Date' => 'September 1 2020',
      'References' =>
              [
                ['CVE', '2020-26948'],
                ['URL', 'https://github.com/btnz-k/emby_ssrf']
              ]              
    )

    register_options(
      [
        Opt::RPORT(8096),
        OptString.new('BASEPATH', [true, 'The base path, usually just /', '/']),
        OptInt.new('TIMEOUT', [true, 'Timeout for the version checker', 30])
      ]
    )
    deregister_options('SSL')
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri' => "#{datastore['BASEPATH']}System/Info/Public",
      'method' => 'GET'
    })
    if res.nil? || res.code != 200
      vprint_error('[Emby Version] failed to connect')
      return
    end

    result = res.get_json_document
    print_status("Identifying Media Server Version on #{peer}")
    print_good("[Media Server] URI: http://#{ip}:#{rport}#{datastore['BASEPATH']}")
    print_good("[Media Server] Version: #{result['Version']}")
    print_good("[Media Server] Internal IP: #{result['LocalAddress']}")
    print_good("*** Vulnerable to SSRF module auxiliary/scanner/emby_ssrf_scanner! ***") if Gem::Version.new("#{result['Version']}") < Gem::Version.new('4.5.0')
    report_service(
      host: rhost,
      port: rport,
      name: 'emby',
      info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})"
    )
    print_status "All info: #{result}" if datastore['VERBOSE']
    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      ntype: 'server_version',
      data: result['Version'],
      info: "Media Server v.#{result['Version']}"
    )
    print_status('Saving host information.')
    report_host(
      host: ip,
      info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})"
    )
  end
end
