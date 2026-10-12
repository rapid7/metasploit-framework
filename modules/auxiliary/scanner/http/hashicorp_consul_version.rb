# frozen_string_literal: true

##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # The Consul UI is a static Ember bundle served without ACL checks; it
  # embeds the running version in an HTML comment and the environment meta
  # tag, e.g. "<!-- CONSUL_VERSION: 2.0.4"
  UI_VERSION_RE = /CONSUL_VERSION:\s*([\d.]+)/
  CONSUL_MARKER_RE = %r{<title>Consul by HashiCorp|consul-ui/config/environment}

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'HashiCorp Consul Version Scanner',
        'Description' => %q{
          This module scans for HashiCorp Consul agents and fingerprints the
          running version. It reads the /v1/agent/self API endpoint and
          extracts the Config.Version field. On agents without ACL enforcement
          (the default) this is unauthenticated; when the agent replies 403
          the module retries with the configured ACL token in the
          X-Consul-Token header. If the agent info API stays unreadable the
          module falls back to the Consul UI at /ui/, whose static HTML leaks
          the exact version in a CONSUL_VERSION comment even when the ACL
          default policy denies everything else.

          Tested against every major GA release since October 2024 (1.20,
          1.21, 1.22, 2.0).
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
        'DefaultOptions' => { 'RPORT' => 8500 }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Base path of the Consul endpoint', '/']),
        OptString.new('Token', [false, 'Consul ACL token for agents that enforce ACLs', ''])
      ]
    )
  end

  def send_agent_self(token = nil)
    request = { 'uri' => normalize_uri(target_uri.path, 'v1', 'agent', 'self') }
    request['headers'] = { 'X-Consul-Token' => token } if token
    send_request_cgi(request)
  end

  # Fetches /v1/agent/self; when the agent denies the anonymous request,
  # retries once with the configured ACL token. Returns [response, token_used].
  def probe_agent_self
    res = send_agent_self
    return [nil, nil] if res.nil?

    if res.code == 403 && !datastore['Token'].to_s.empty?
      token = datastore['Token']
      auth_res = send_agent_self(token)
      return [nil, nil] if auth_res.nil?

      return [auth_res, token] if auth_res.code == 200
    end
    [res, nil]
  end

  # Pulls the version out of an /v1/agent/self response.
  def version_details(res)
    json = res.get_json_document
    json.is_a?(Hash) ? json.dig('Config', 'Version') : nil
  end

  def detect_ui_version
    # the UI index redirects to its trailing-slash form, so ask for that
    # directly instead of following the redirect
    ui_uri = "#{normalize_uri(target_uri.path, 'ui')}/"
    res = send_request_cgi('uri' => ui_uri)

    return [false, nil, nil] unless res

    body = res.body.to_s
    if body =~ CONSUL_MARKER_RE
      return [true, " (Consul UI at #{ui_uri})", body[UI_VERSION_RE, 1]]
    end

    [false, nil, nil]
  end

  def report_consul(summary)
    report_service(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: ssl ? 'https' : 'http',
      info: summary
    )
  end

  def run_host(_ip)
    res, token = probe_agent_self
    if res.nil?
      print_error("No response from #{rhost}:#{rport}")
      return
    end

    version = res.code == 200 ? version_details(res) : nil

    if version
      print_good("HashiCorp Consul #{version} found")

      if token
        print_status('Version retrieved with the supplied ACL token')
      else
        print_status('No authentication required to read the agent info API')
        if res.headers['X-Consul-Default-Acl-Policy'].to_s =~ /allow/i
          print_status('ACL default policy is allow (no ACL enforcement)')
        end
      end

      report_consul("HashiCorp Consul #{version}")
      return
    end

    found, hint, ui_version = detect_ui_version
    if found
      if ui_version
        print_good("HashiCorp Consul #{ui_version} identified from the UI version leak#{hint}, though the agent info API returned HTTP #{res.code}")
        report_consul("HashiCorp Consul #{ui_version}")
      else
        print_status("Consul UI detected#{hint}, but the version could not be determined (agent info API returned HTTP #{res.code})")
        report_consul('HashiCorp Consul (version unknown)')
      end
    elsif res.code == 403
      print_status('ACLs enabled (HTTP 403) and no token worked; the version could not be determined')
    elsif res.code == 404
      print_status('Target does not appear to be a Consul agent (no /v1/agent/self)')
    else
      print_status('Target does not appear to be a Consul agent')
    end
  end
end
