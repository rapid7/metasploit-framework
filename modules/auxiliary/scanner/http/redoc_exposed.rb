##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Scanner
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ReDoc API Docs UI Exposed',
        'Description' => %q{
          Detects publicly exposed ReDoc API documentation pages.
          The module performs safe, read-only GET requests and reports likely
          ReDoc instances based on HTML markers.
        },
        'Author' => [
          'Hamza Sahin (@hamzasahin61)'
        ],
        'License' => MSF_LICENSE
      )
    )

    register_options(
      [
        Opt::RPORT(80),
        OptBool.new('SSL', [true, 'Negotiate SSL/TLS for outgoing connections', false]),
        OptString.new('REDOC_PATHS', [
          false,
          'Comma-separated list of paths to probe (overrides defaults)',
          nil
        ])
      ]
    )
  end

  # returns true if the response looks like a ReDoc page
  def redoc_like?(res)
    return false unless res && res.code.between?(200, 403)

    # Prefer DOM checks
    doc = res.get_html_document
    if doc
      return true if doc.at_css('redoc, redoc-, #redoc')
      return true if doc.css('script[src*="redoc"]').any?
      return true if doc.css('script[src*="redoc.standalone"]').any?
    end

    # Fallback to body/title heuristics
    title = res.get_html_title.to_s
    body  = res.body.to_s

    return true if title =~ /redoc/i
    return true if body =~ /<redoc-?/i
    return true if body =~ /redoc(\.standalone)?\.js/i

    false
  end

  def check_path(path)
    res = send_request_cgi({ 'method' => 'GET', 'uri' => normalize_uri(path) })
    redoc_like?(res)
  end

  def run_host(ip)
    vprint_status("#{ip} - scanning for ReDoc")

    paths =
      if (ds = datastore['REDOC_PATHS']) && !ds.empty?
        ds.split(',').map(&:strip)
      else
        ['/redoc', '/redoc/', '/docs', '/api/docs', '/openapi']
      end

    hit = paths.find { |p| check_path(p) }
    if hit
      print_good("#{ip} - ReDoc likely exposed at #{hit}")
      report_service(host: ip, port: rport, proto: 'tcp', name: 'http')
    else
      vprint_status("#{ip} - no ReDoc found")
    end
  end
end
