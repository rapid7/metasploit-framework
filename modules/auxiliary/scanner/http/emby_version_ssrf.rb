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
      'Name' => 'Emby Version Scanner',
      'Description' => 'This module attempts to identify the version of an Emby Media Server running on a
                        host. If you wish to see all the information available, set VERBOSE to true. Use in
                        conjunction with emby_ssrf_scanner to locate devices vulnerable to CVE-2020-26948.',
      'Author' => 'Btnz',
      'License' => MSF_LICENSE,
      'Disclosure Date' => '2020-10-01',
      'RelatedModules' => ['auxiliary/scanner/http/emby_ssrf_scanner'],
      'References' => [
        ['CVE', '2020-26948'],
        ['URL', 'https://github.com/btnz-k/emby_ssrf']
      ]
    )

    register_options(
      [
        Opt::RPORT(8096),
        OptString.new('TARGETURI', [true, 'The base path, usually just /', '/']),
        OptInt.new('TIMEOUT', [true, 'Timeout for the version scanner', 30])
      ]
    )
    deregister_options('SSL')
  end

  def run_host(ip)
    res = send_request_cgi({
      'uri' => "#{datastore['TARGETURI']}System/Info/Public",
      'method' => 'GET'
    }, datastore['TIMEOUT'])
    if res.nil? || res.code != 200
      print_error('Failed to connect to an Emby Server')
      return
    end

    result = res.get_json_document
    print_status("Identifying Media Server Version on #{peer}")
    print_good("[Media Server] URI: http://#{peer}#{datastore['TARGETURI']}")
    print_good("[Media Server] Version: #{result['Version']}")
    print_good("[Media Server] Internal IP: #{result['LocalAddress']}") if ((result['LocalAddress']).to_s) != ''
    print_good('*** Vulnerable to SSRF module auxiliary/scanner/http/emby_ssrf_scanner! ***') if Rex::Version.new((result['Version']).to_s) < Rex::Version.new('4.5.0')
    report_service(
      host: rhost,
      port: rport,
      name: 'emby',
      info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})"
    )
    vprint_status "All info: #{result}"
    report_note(
      host: ip,
      port: rport,
      proto: 'tcp',
      ntype: 'server_version',
      data: result['Version'],
      info: "Media Server v.#{result['Version']}"
    )
    vprint_status('Saving host information.')
    report_host(
      host: ip,
      info: "Emby Server v.#{result['Version']} (LAN:#{result['LocalAddress']})"
    )
  end
end
