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
      'Name' => 'HTTP Options Detection',
      'Description' => 'Display available HTTP options for each system',
      'Author' => ['CG'],
      'License' => MSF_LICENSE,
      'References' => [
        ['CVE', '2005-3398'], # HTTP Trace related
        ['CVE', '2005-3498'], # HTTP Trace related
        ['OSVDB', '877'],
        ['BID', '11604'],
        ['BID', '9506'],
        ['BID', '9561'],
        ['URL', 'https://developer.mozilla.org/en-US/docs/Web/HTTP/Methods/OPTIONS']
      ]
    )
    register_options(
      [
        OptString.new('TARGETURI', [true, 'URI to test', '/']),
      ]
    )
  end

  def run_host(target_host)
    res = send_request_cgi({
      'uri' => datastore['TARGETURI'],
      'method' => 'OPTIONS'
    })
    return unless res

    # Patch so that we can catch a Tomcat edge case.
    # Tomcat may respond to OPTIONS requests with the verbs in the
    # HTTP body, instead of the Allow header.
    # https://github.com/rapid7/metasploit-framework/issues/12557#issuecomment-552263162
    # https://stackoverflow.com/questions/23886941/http-status-405-jsps-only-permit-get-post-or-head
    if res.body && res.body =~ %r{<h1>HTTP Status 405 - JSPs only permit ([^<]*)</h1>}
      res.headers['Allow'] = ::Regexp.last_match(1).sub(' or ', ' ').gsub(' ', ', ')
    end

    unless res.headers['Allow']
      vprint_error("#{target_host} missing Allow header")
      return
    end

    allowed_methods = res.headers['Allow']

    print_good("#{target_host} allows #{allowed_methods} methods")

    report_note(
      host: target_host,
      proto: 'tcp',
      sname: (ssl ? 'https' : 'http'),
      port: rport,
      type: 'HTTP_OPTIONS',
      data: allowed_methods
    )

    if allowed_methods.index('TRACE')
      print_good "#{target_host}:#{rport} - TRACE method allowed."
      report_vuln(
        host: target_host,
        port: rport,
        proto: 'tcp',
        sname: (ssl ? 'https' : 'http'),
        name: 'HTTP Trace Method Allowed',
        info: "Module #{fullname} detected TRACE access through the Allow header: #{allowed_methods}",
        refs: references,
        exploited_at: Time.now.utc
      )
    end
  rescue ::Rex::ConnectionRefused, ::Rex::HostUnreachable, ::Rex::ConnectionTimeout
  rescue ::Timeout::Error, ::Errno::EPIPE
  end
end
