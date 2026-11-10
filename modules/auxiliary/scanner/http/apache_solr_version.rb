# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  SPEC_VERSION_RE = /"solr-spec-version"\s*:\s*"([^"]+)"/
  SOLR_MARKER_RE = /solrAdminApp|<title>Solr Admin|Apache-Solr/i
  # The admin UI cache-busts its asset URLs with the running version
  # (e.g. login.css?_=9.8.1), present on the unauthenticated index and login
  # pages of every Solr release tested from 8.1 through 10.0
  ASSET_VERSION_RE = /[?&]_=(\d+\.\d+(?:\.\d+)?)/

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Apache Solr Version Scanner',
        'Description' => %q{
          This module scans for Apache Solr instances and fingerprints the
          running version. It reads the /admin/info/system handler (JSON)
          beneath the configured TARGETURI (/solr by default, Solr's built-in
          hostContext) and extracts the solr-spec-version field. When the
          handler is protected by basic authentication the module retries with
          the configured credentials, which default to the secure-by-default
          solr:SolrRocks account introduced in Solr 9.8.0, reporting when they
          are accepted. If the handler stays unreadable the module falls back
          to the admin UI pages, whose asset URLs leak the running version
          even before authentication. The result is recorded as service
          evidence for the host.

          Tested against 8.1.1-10.0.0 on major and minor versions.
        },
        'Author' => [
          'h00die'
        ],
        'License' => MSF_LICENSE,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        },
        'DefaultOptions' => { 'RPORT' => 8983 }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Path to the Solr webapp', '/solr']),
        OptString.new('Username', [false, 'Basic auth username', 'solr']),
        OptString.new('Password', [false, 'Basic auth password', 'SolrRocks'])
      ]
    )
  end

  def send_system_info(auth = nil)
    request = {
      'uri' => normalize_uri(target_uri.path, 'admin', 'info', 'system'),
      'vars_get' => { 'wt' => 'json' }
    }
    if auth
      request['username'] = auth[:user]
      request['password'] = auth[:pass]
    end
    send_request_cgi(request)
  end

  # Fetches /admin/info/system; on an authentication challenge retries once
  # with the configured credentials. Returns [response, auth_used].
  def probe_system_info
    res = send_system_info
    return [nil, nil] if res.nil?

    if [401, 403].include?(res.code) && !datastore['Username'].to_s.empty?
      candidate = { user: datastore['Username'].to_s, pass: datastore['Password'].to_s }
      auth_res = send_system_info(candidate)
      return [nil, nil] if auth_res.nil?

      return [auth_res, candidate] if auth_res.code == 200
    end
    [res, nil]
  end

  # Pulls the version fields out of an /admin/info/system response, with a
  # regex fallback for JSON responses the parser chokes on.
  def version_details(res)
    details = {}
    json = res.get_json_document
    if json.is_a?(Hash) && json['lucene'].is_a?(Hash)
      details[:solr] = json['lucene']['solr-spec-version']
      details[:lucene] = json['lucene']['lucene-spec-version']
    end
    details[:solr] ||= res.body[SPEC_VERSION_RE, 1]
    details.compact
  end

  # Confirms Solr is present when /admin/info/system is unreadable, via the
  # admin UI page or its authentication challenge. The UI page (served without
  # authentication even on hardened installs) may leak the exact version
  # through its asset cache-busters, which is returned when present.
  def detect_solr_marker
    # the webapp root 302-redirects to its trailing-slash form, so ask for
    # that directly instead of following the redirect
    ui_uri = "#{target_uri.path.chomp('/')}/"
    res = send_request_cgi('method' => 'GET', 'uri' => ui_uri)
    return [false, nil, nil] unless res

    body = res.body.to_s

    if body =~ SOLR_MARKER_RE
      return [true, " (admin UI at #{ui_uri})", body[ASSET_VERSION_RE, 1]]
    end

    challenge = res.headers['WWW-Authenticate'].to_s
    if [401, 403].include?(res.code) && challenge =~ /solr/i
      return [true, " (auth challenge at #{ui_uri})", nil]
    end

    [false, nil, nil]
  end

  def report_solr(summary)
    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: ssl ? 'https' : 'http',
      info: summary
    )
  end

  def run_host(_ip)
    res, auth = probe_system_info
    if res.nil?
      print_error("No response from #{rhost}:#{rport}")
      return
    end

    details = res.code == 200 ? version_details(res) : {}

    if details[:solr]
      summary = "Apache Solr #{details[:solr]}"
      if details[:lucene] && details[:lucene] != details[:solr]
        summary += " (Lucene #{details[:lucene]})"
      end
      print_good("#{summary} found at #{target_uri.path}")

      if auth
        if auth[:user] == 'solr' && auth[:pass] == 'SolrRocks'
          print_warning('Secure-by-default credentials solr:SolrRocks accepted (Solr >= 9.8.0)')
          report_note(
            host: rhost,
            port: rport,
            type: 'apache_solr.default_creds',
            data: { user: 'solr', pass: 'SolrRocks' },
            update: :unique_data
          )
        else
          print_status("Version retrieved with the supplied credentials (#{auth[:user]})")
        end
      else
        print_status('No authentication required to read the admin info handler')
      end

      report_solr(summary)
      return
    end

    marker, hint, ui_version = detect_solr_marker
    if marker
      if ui_version
        summary = "Apache Solr #{ui_version}"
        print_good("#{summary} identified from admin UI asset versions#{hint}, though the admin info handler returned HTTP #{res.code}")
        report_solr(summary)
      else
        print_status("Apache Solr detected#{hint}, but the version could not be determined (admin info handler returned HTTP #{res.code})")
        report_solr('Apache Solr (version unknown)')
      end
    elsif [401, 403].include?(res.code)
      print_status("Authentication required (HTTP #{res.code}) and the configured credentials did not work; could not confirm Apache Solr or its version")
    elsif res.code == 404
      print_status("No Solr webapp at #{target_uri.path}; set TARGETURI if it is mounted elsewhere")
    else
      print_status('Target does not appear to be Apache Solr')
    end
  end
end
