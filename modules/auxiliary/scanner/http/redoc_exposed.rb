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
          'SideEffects' => []           # Add IOC_IN_LOGS if server logs may record these requests
        },
        'DefaultOptions' => {
          'RPORT' => 80
          # SSL is registered by default; set here only if you want a non-default value
          # 'SSL' => false
        }
      )
    )

    register_options(
      [
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

    paths =
      if datastore['REDOC_PATHS'].to_s.empty?
        ['/redoc', '/redoc/', '/docs', '/api/docs', '/openapi']
      else
        datastore['REDOC_PATHS'].split(',').map(&:strip)
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
