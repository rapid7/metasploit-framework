##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name' => 'FortiMail Unauthenticated Login Bypass Scanner',
      'Description' => %q{
        This module attempts to detect instances of FortiMail vulnerable
        against an unauthenticated login bypass (CVE-2020-9294).
      },
      'Author' => [
        'Mike Connor', # Initial Vulnerability discovery
        'Juerg Schweingruber <juerg.schweingruber[at]redguard.ch>', # Vulnerability Re-Discovery
        'Patrick Schmid <patrick.schmid[at]redguard.ch>' # Exploit Development & MSF module
      ],
      'References' => [
        ['CVE', '2020-9294'],
        ['URL', 'https://fortiguard.com/psirt/FG-IR-20-045'],
        ['URL', 'https://www.redguard.ch/blog/2020/07/02/fortimail-unauthenticated-login-bypass/']
      ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the FortiMail admin page', '/admin/AdminLogin.html']),
      Opt::RPORT(443)
    ])

    register_advanced_options([
      OptBool.new('SSL', [true, 'Negotiate SSL connection', true])
    ])
  end

  def target_url
    proto = 'http'
    if (rport == 443) || ssl
      proto = 'https'
    end
    uri = normalize_uri(datastore['URI'])
    "#{proto}://#{vhost}:#{rport}#{uri}"
  end

  def run_host(ip)
    vprint_status("Checking vulnerability at #{ip}")
    uri = normalize_uri(target_uri.path)

    res = send_request_raw({
      'method' => 'GET',
      'uri' => uri
    })

    return :abort unless res # prints default connection error messages

    if res.code == 301
      vprint_error("#{ip} - Page redirect to #{res.headers['Location']}")
      return :abort
    end

    unless res.code == 200
      vprint_bad("#{ip} - No version of FortiMail detected")
      return :abort
    end

    version_raw = res.body[/fml-admin-login-(\d+).js/, 1]
    version = version_raw.to_i
    unless (res.body.include?('newpassword') && (version.between?(140, 160) || version.between?(730, 745) || version.between?(250, 263)))
      print_bad("#{ip} - Not vulnerable version (Build: #{version_raw}) of FortiMail detected")
      return :abort
    end

    print_good("#{ip} - Vulnerable version (Build: #{version_raw}) of FortiMail detected")

    report_vuln(
      host: rhost,
      port: rport,
      name: 'FortiMail Login Bypass',
      refs: references
    )
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    # noop
  rescue ::Timeout::Error, ::Errno::EPIPE
    # noop
  rescue ::OpenSSL::SSL::SSLError => e
    return if (e.to_s.match(/^SSL_connect /)) # strange errors / exception if SSL connection aborted
  end
end
