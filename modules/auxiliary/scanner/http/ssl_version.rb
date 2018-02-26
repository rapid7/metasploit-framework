##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'HTTP SSL/TLS Version Detection (POODLE scanner)',
      'Description' => %q{
        Check if an HTTP server supports a given version of SSL/TLS.

        If a web server can successfully establish an SSLv3 session, it is
        likely to be vulnerable to the POODLE attack described on
        October 14, 2014, as a patch against the attack is unlikely.
      },
      'Author'      => 'todb',
      'License'     => MSF_LICENSE,
      'DefaultOptions' =>
      {
        'SSL' => true,
        'RPORT' => 443,
      },
      'References'  =>
      [
        [ 'URL', 'http://googleonlinesecurity.blogspot.com/2014/10/this-poodle-bites-exploiting-ssl-30.html'],
        [ 'OSVDB', '113251'],
        [ 'CVE', '2014-3566']
      ],
      'DisclosureDate' => 'Oct 14 2014'
    )

    register_options(
      [
        Opt::SSLVersion
      ]
    )

  end

  # Fingerprint a single host
  def run_host(ip)
    begin
      res = send_request_raw({ 'uri' => '/', 'method' => 'GET' })
      fp = http_fingerprint(:response => res)
      if fp
        vprint_status("#{peer} connected and fingerprinted: #{fp}")
        # TODO: Interrogate the connection itself to see what version
        # was used. Where that actually lives is eluding me. :/
        if datastore['SSL'] && datastore['SSLVersion'] == 'SSL3'
          print_good("#{peer} accepts SSLv3")
          report_poodle_vuln(ip)
        end
      end
    rescue ::OpenSSL::SSL::SSLError => e
      ssl_version = e.message.match(/ state=([^\s]+)/)[1]
      vprint_status("#{peer} does not accept #{ssl_version}")
    end
  end

  def report_poodle_vuln(ip)
    report_vuln(
      :host         => ip,
      :port         => rport,
      :proto        => 'tcp',
      :name         => self.name,
      :info         => "Module #{self.fullname} confirmed SSLv3 is available",
      :refs         => self.references,
      :exploited_at => Time.now.utc
    )
  end
end
