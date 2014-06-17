##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit3 < Msf::Auxiliary

  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report
  include Msf::Proto::SSL

  def initialize
    super(
      'Name'           => 'OpenSSL Server-Side ChangeCipherSpec Injection Scanner',
      'Description'    => %q{
        This module checks for the OpenSSL ChageCipherSpec (CCS)
        Injection vulnerability. The problem exists in the handling of early
        CCS messages during session negotation. Vulnerable installations of OpenSSL accepts
        them, while later implementations do not. If successful, an attacker can leverage this
        vulnerability to perform a man-in-the-middle (MITM) attack by downgrading the cipher spec
        between a client and server. This issue was first reported in early June, 2014.
      },
      'Author'         => [
        'Masashi Kikuchi', # Vulnerability discovery
        'Craig Young <CYoung[at]tripwire.com>', # Original Scanner. This module is based on it.
        'juan vazquez' # Msf module
      ],
      'References'     =>
        [
          ['CVE', '2014-0224'],
          ['URL', 'http://ccsinjection.lepidum.co.jp/'],
          ['URL', 'http://ccsinjection.lepidum.co.jp/blog/2014-06-05/CCS-Injection-en/index.html'],
          ['URL', 'http://www.tripwire.com/state-of-security/incident-detection/detection-script-for-cve-2014-0224-openssl-cipher-change-spec-injection/'],
          ['URL', 'https://www.imperialviolet.org/2014/06/05/earlyccs.html']
        ],
      'DisclosureDate' => 'Jun 5 2014',
      'License'        => MSF_LICENSE
    )
  end

  def peer
    "#{rhost}:#{rport}"
  end

  def run_host(ip)
    ccs_injection
  end

  def ccs_injection
    connect_result = establish_connect
    return if connect_result.nil?

    vprint_status("#{peer} - Sending CCS...")
    sock.put(change_cipher_spec)
    alert = sock.get_once(-1, response_timeout)
    if alert.blank?
      print_good("#{peer} - No alert after invalid CSS message, probably vulnerable")
      report
    elsif alert.unpack("C").first == RECORD_TYPE_ALERT
      vprint_error("#{peer} - Alert record as response to the invalid CCS Message, probably not vulnerable")
    elsif alert
      vprint_warning("#{peer} - Unexpected response.")
    end
  end

  def report
    report_vuln({
      :host => rhost,
      :port => rport,
      :name => self.name,
      :refs => self.references,
      :info => "Module #{self.fullname} successfully detected CCS injection"
    })
  end

end
