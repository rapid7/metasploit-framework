##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'HTTP Host Header Injection Detection',
      'Description' => 'Checks if the host is vulnerable to Host header injection',
      'Author'      =>
        [
          'Jay Turla', # @shipcod3
          'Medz Barao' # @godflux
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2016-10073'], # validate, an instance of a described attack approach from the original reference
          ['URL', 'http://www.skeletonscribe.net/2013/05/practical-http-host-header-attacks.html']
        ]
    ))

    register_options([
      OptString.new('PATH', [true, "The PATH to use while testing", '/']),
      OptEnum.new('METHOD', [true, 'HTTP Request Method', 'GET', ['GET', 'POST']]),
      OptString.new('TARGETHOST', [false, 'The redirector target. Default is <random>.com']),
      OptString.new('DATA', [false, 'POST data, if necessary', '']),
      OptBool.new('SHOW_EVIDENCE', [false, "Show evidences: headers or body", false])
    ])
  end

  def run_host(ip)

    web_path = normalize_uri(datastore['PATH'])
    http_method = datastore['METHOD']
    target_host = datastore['TARGETHOST'] || Rex::Text.rand_text_alpha_lower(8)+".com"

    # The 'Host' header specifies the domain name of the server (for virtual
    # hosting), and (optionally) the TCP port number on which the server is listening.

    # The 'X-Host' header specifies the originating domain name of the server
    # (for virtual hosting) and optionally the TCP port number.

    # The 'X-Forwarded-Host' header is a de-facto standard header for identifying
    # the original host requested by the client in the Host HTTP request header.

    begin

      vprint_status("Sending request #{rhost}:#{rport}#{web_path} (#{vhost})(#{http_method}) with 'Host' value '#{target_host}'")

      res = send_request_raw({
        'uri'     => web_path,
        'method'  => http_method,
        'data'    => datastore['DATA'],
        'headers' => {
          'Host'             => target_host,
          'X-Host'           => target_host,
          'X-Forwarded-Host' => target_host
        }
      })

      unless res
        vprint_error("#{rhost}:#{rport}#{web_path} (#{vhost}) did not reply to our request")
        return
      end

      if res.headers.include?(target_host)
        evidence = "headers"
        if datastore['SHOW_EVIDENCE']
          vprint_status("Headers: [#{res.headers}]")
        end
      end

      if res.body.include?(target_host)
        evidence = "body"
        if datastore['SHOW_EVIDENCE']
          vprint_status("Body: [#{res.body}]")
        end
      end

      if evidence
        print_good("#{rhost}:#{rport}#{web_path} (#{vhost})(#{res.code})(#{http_method})(evidence into #{evidence}) is vulnerable to HTTP Host header injection")

        report_vuln(
          host:  rhost,
          port:  rport,
          proto: 'tcp',
          sname: ssl ? 'https' : 'http',
          name:  self.name,
          info:  "Module used #{self.fullname}, vhost: #{vhost}, method: #{http_method}: evidence: #{evidence}",
          refs:  self.references
        )

        report_web_vuln({
          :host        => rhost,
          :port        => rport,
          :vhost       => vhost,
          :path        => web_path,
          :pname       => "Host,X-Host,X-Forwarded-Host headers",
          :risk        => 2,
          :proof       => "Evidence into #{evidence}",
          :description => "HTTP Host Header Injection Detection",
          :name        => self.fullname,
          :category    => "web",
          :method      => http_method
        })

      else
        vprint_error("#{rhost}:#{rport}#{web_path} (#{vhost}) returned #{res.code} #{res.message}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
