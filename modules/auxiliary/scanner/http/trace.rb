##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::WmapScanServer
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'HTTP Cross-Site Tracing Detection',
      'Description' => 'Checks if the host is vulnerable to Cross-Site Tracing (XST)',
      'Author'      =>
        [
          'Jay Turla <@shipcod3>' , #Cross-Site Tracing (XST) Checker
          'CG' #HTTP TRACE Detection
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          ['CVE', '2005-3398'], # early case where this vector applied to a specific application.
          ['URL', 'https://www.owasp.org/index.php/Cross_Site_Tracing']
        ]
    )
    register_options(
      [
        OptString.new('PATH', [ true, "The PATH to use while testing", '/']),
        OptInt.new('TIMEOUT', [true, 'The socket connect/read timeout in seconds', 20]),
        OptBool.new('COOKIE_CHECK', [ false, "Check for Cookie header also", false ])
      ]
    )
  end

  def run_host(target_host)

    timeout = datastore['TIMEOUT']

    rand_payload = Rex::Text.rand_text_alpha(5 + rand(8))

    web_path = normalize_uri(datastore['PATH'])
    xst_payload = "<script>alert(#{rand_payload})</script>" # XST Payload
    check_uri = web_path + xst_payload

    begin

      if datastore['COOKIE_CHECK']
        vprint_status("Sending request #{rhost}:#{rport} (vhost: #{vhost}) with Cookie header check")
        res = send_request_raw({
          'uri'    => check_uri,
          'method' => 'TRACE',
          'headers' => {
            'Cookie' => "name=#{xst_payload}"
          },
        }, timeout)
      else
        vprint_status("Sending request #{rhost}:#{rport} (vhost: #{vhost})")
        res = send_request_raw({
          'uri'    => check_uri,
          'method' => 'TRACE',
        }, timeout)
      end

      unless res
        vprint_error("#{rhost}:#{rport} (vhost: #{vhost})[#{res.code}] did not reply to our request")
        return
      end

      if res.body.to_s.index("#{web_path}#{xst_payload}")
        print_good("#{rhost}:#{rport} (vhost: #{vhost})[#{res.code}] is vulnerable to Cross-Site Tracing")

        vprint_status("#{rhost}:#{rport} (vhost: #{vhost})[#{res.code}] Response: [#{res.body.to_s}]")

        report_vuln({
          :host  => rhost,
          :port  => rport,
          :proto => 'tcp',
          :sname => (ssl ? 'https' : 'http'),
          :name  => self.name,
          :info  => "Module used #{self.fullname}, vhost: #{vhost}",
          :refs  => self.references
        })

        report_web_vuln({
          :host        => rhost,
          :port        => rport,
          :vhost       => vhost,
          :path        => web_path,
          :pname       => xst_payload,
          :risk        => 2,
          :proof       => "#{xst_payload} payload with TRACE method",
          :description => "Vulnerable to Cross-Site Tracing",
          :name        => self.fullname,
          :category    => "web",
          :method      => "GET" # specifing TRACE... Error: "ActiveRecord" "RecordInvalid" "Method is not included in the list"
        })

      else
        vprint_error("#{rhost}:#{rport} (vhost: #{vhost}) returned #{res.code} #{res.message}")
      end

    rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
    rescue ::Timeout::Error, ::Errno::EPIPE
    end
  end
end
