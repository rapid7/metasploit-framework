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
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],  # GET requests only; should not crash or disrupt the target service
          'Reliability' => [],          # Does not establish sessions; leaving this empty is acceptable
          'SideEffects' => [IOC_IN_LOGS] # Requests may be logged by the target web server
        },
        'DefaultOptions' => {
          'RPORT' => 80
        }
      )
    )

    register_options(
      [
        # Mark as required and surface the built-in defaults here
        OptString.new('REDOC_PATHS', [
          true,
          'Comma-separated list of paths to probe',
          '/redoc,/redoc/,/docs,/api/docs,/openapi'
        ])
      ]
    )
  end

  # returns true if the response looks like a ReDoc page
  def redoc_like?(res)
    # Accept only 2xx or 403 (exclude redirects; many 3xx lack HTML to analyze)
    return false unless res && (res.code.between?(200, 299) || res.code == 403)

    # Prefer DOM checks
    doc = res.get_html_document
    if doc && (doc.at_css('redoc, redoc-, #redoc') ||
               doc.css('script[src*="redoc"]').any? ||
               doc.css('script[src*="redoc.standalone"]').any?)
      return true
    end

    # Fallback to body/title heuristics
    title = res.get_html_title.to_s
    body = res.body.to_s
    return true if title =~ /redoc/i || body =~ /<redoc-?/i || body =~ /redoc(\.standalone)?\.js/i

    false
  end

  def check_path(path)
    redoc_like?(send_request_cgi({ 'method' => 'GET', 'uri' => normalize_uri(path) }))
  end

  def run_host(ip)
    vprint_status("#{ip} - scanning for ReDoc")

    # REDOC_PATHS is required and has defaults; always use it directly
    paths = datastore['REDOC_PATHS'].split(',').map(&:strip)

    hit = paths.find { |p| check_path(p) }
    if hit
      print_good("#{ip} - ReDoc likely exposed at #{hit}")
      report_service(host: ip, port: rport, proto: 'tcp', name: 'http')
    else
      vprint_status("#{ip} - no ReDoc found")
    end
  end
end
