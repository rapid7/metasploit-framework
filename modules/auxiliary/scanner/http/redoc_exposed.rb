require 'msf/core'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'ReDoc API Docs UI Exposed',
        'Description' => %q{
          Detects publicly exposed ReDoc API documentation pages which may reveal API surface,
          endpoints, request/response models, and other implementation details useful to attackers.
        },
        'Author' => [
          'Hamza Sahin <hmzshn61@gmail.com>'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          [ 'URL', 'https://redocly.com/docs/redoc/' ]
        ],
        'Actions' => [ [ 'Scan', { 'Description' => 'Scan for exposed ReDoc UI' } ] ],
        'DefaultAction' => 'Scan'
      )
    )

    register_advanced_options([
      OptString.new('REDOC_PATHS', [ true, 'Comma-separated paths to probe', '/redoc,/docs,/api/docs,/openapi,/redoc/' ])
    ])
  end

  # Returns :yes if the path looks like a ReDoc page, else :no
  def check_path(path)
    res = send_request_cgi({ 'method' => 'GET', 'uri' => normalize_uri(path) }, 10)
    return :no if res.nil?

    code_ok = res.code && res.code.between?(200, 403)
    body = res.body.to_s

    title_hit = body =~ /<\s*title[^>]*>[^<]*redoc[^<]*<\/\s*title\s*>/i
    redoc_hit = body =~ /(redoc(?:\.standalone)?\.js|<\s*redoc-?)/i

    return :yes if code_ok && (title_hit || redoc_hit)
    :no
  end

  def run_host(ip)
    vprint_status("#{ip} - scanning for ReDoc")

    paths = (datastore['REDOC_PATHS'] || '').split(',').map(&:strip)
    paths = ['/redoc', '/docs', '/api/docs', '/openapi', '/redoc/'] if paths.empty?

    hit = paths.find { |p| check_path(p) == :yes }

    if hit
      print_good("#{ip} - ReDoc likely exposed at #{hit}")
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: (ssl ? 'https' : 'http')
      )
      report_note(
        host: ip,
        port: rport,
        proto: 'tcp',
        type: 'http.redoc.exposed',
        data: { path: hit }
      )
    else
      vprint_status("#{ip} - no ReDoc found")
    end
  end
end
