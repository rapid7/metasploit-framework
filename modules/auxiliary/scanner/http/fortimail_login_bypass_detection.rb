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
        against an unauthenicated login bypass (CVE-2020-9294).
      },
      'Author'         => [
        'Mike Connor', # Initial Vulnerability discovery
        'Juerg Schweingruber <juerg.schweingruber@redguard.ch>', # Vulnerability Re-Discovery
        'Patrick Schmid <patrick.schmid@redguard.ch>' # Exploit Development & MSF module
      ],
      'References' =>
        [
          ['URL',   'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-9294'],
          ['URL',   'https://fortiguard.com/psirt/FG-IR-20-045']
        ],
      'License' => MSF_LICENSE
    )

    register_options([
      OptString.new('TARGETURI', [true, 'Path to the FortiMail admin page', '/admin/AdminLogin.html']),
      OptInt.new('RPORT', [true, "Default remote port", 443])
    ])

    register_advanced_options([
      OptBool.new('SSL', [true, "Negotiate SSL connection", true])
    ])
  end

  def target_url
    proto = "http"
    if rport == 443 or ssl
      proto = "https"
    end
    uri = normalize_uri(datastore['URI'])
    "#{proto}://#{vhost}:#{rport}#{uri}"
  end

  def run_host(ip)
    print_status("Checking vulnerability at #{ip}")
    uri = normalize_uri(target_uri.path)
    begin
      res = send_request_raw({
        'method' => 'GET',
        'uri' => uri
        })

      if (res and res.code == 200 and res.body.include? "newpassword" and res.body.include? "fml-admin-login-0160.js")
        print_good("#{ip} - Vulnerable version of FortiMail found")
      elsif (res and res.code == 301)
        print_error("#{target_url} - Page redirect to #{res.headers['Location']}")
        return :abort
      else
        print_bad("#{ip} - Not vulnerable version of FortiMail found")
        return :abort
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    rescue ::OpenSSL::SSL::SSLError => e
      return if(e.to_s.match(/^SSL_connect /) ) # strange errors / exception if SSL connection aborted
    end
  end
end
